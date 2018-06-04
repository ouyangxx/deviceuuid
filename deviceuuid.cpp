#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <iostream>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
//#include <linux/hdreg.h>
//#include <linux/if.h>
#include <fcntl.h>
#endif
#include "deviceuuid.h"
#include "openssl/md5.h"
#if _MSC_VER
#define snprintf _snprintf
#endif


#ifdef WIN32
#include <windows.h>
#include <winioctl.h>
// IOCTL
#if(_WIN32_WINNT < 0x0400)
#define SMART_GET_VERSION				0x00074080
#define SMART_RCV_DRIVE_DATA			0x0007c088
#endif
#define FILE_DEVICE_SCSI				0x0000001b
#define IOCTL_SCSI_MINIPORT_IDENTIFY	((FILE_DEVICE_SCSI << 16) + 0x0501)
#define IOCTL_SCSI_MINIPORT				0x0004D008

// IDEREGS
#define IDE_ATAPI_IDENTIFY		0xA1
#define IDE_ATA_IDENTIFY		0xEC
#define IDENTIFY_BUFFER_SIZE	512
#define SENDIDLENGTH			sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE

typedef struct _GETVERSIONOUTPARAMS
{
	BYTE bVersion;
	BYTE bRevision;
	BYTE bReserved;
	BYTE bIDEDeviceMap;
	DWORD fCapabilities;
	DWORD dwReserved[4];
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

typedef struct _IDSECTOR
{
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[3];
	CHAR    sSerialNumber[20];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[8];
	CHAR    sModelNumber[40];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[128];
} IDSECTOR, *PIDSECTOR;

typedef struct _SRB_IO_CONTROL
{
	ULONG HeaderLength;
	UCHAR Signature[8];
	ULONG Timeout;
	ULONG ControlCode;
	ULONG ReturnCode;
	ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;

#if(_WIN32_WINNT < 0x0400)
typedef struct _DRIVERSTATUS {
	UCHAR bDriverError;
	UCHAR bIDEError;
	UCHAR bReserved[2];
	ULONG dwReserved[2];
} DRIVERSTATUS, *PDRIVERSTATUS, *LPDRIVERSTATUS;

typedef struct _SENDCMDOUTPARAMS {
	ULONG        cBufferSize;
	DRIVERSTATUS DriverStatus;
	UCHAR        bBuffer[1];
} SENDCMDOUTPARAMS, *PSENDCMDOUTPARAMS, *LPSENDCMDOUTPARAMS;

typedef struct _IDEREGS {
	UCHAR bFeaturesReg;
	UCHAR bSectorCountReg;
	UCHAR bSectorNumberReg;
	UCHAR bCylLowReg;
	UCHAR bCylHighReg;
	UCHAR bDriveHeadReg;
	UCHAR bCommandReg;
	UCHAR bReserved;
} IDEREGS, *PIDEREGS, *LPIDEREGS;

typedef struct _SENDCMDINPARAMS {
	ULONG   cBufferSize;
	IDEREGS irDriveRegs;
	UCHAR   bDriveNumber;
	UCHAR   bReserved[3];
	ULONG   dwReserved[4];
	UCHAR   bBuffer[1];
} SENDCMDINPARAMS, *PSENDCMDINPARAMS, *LPSENDCMDINPARAMS;
#endif

// 获取IDE硬盘序列号(只支持Windows NT/2000/XP以上操作系统)
bool GetIDEHDSerial(int driveNum, std::string& serialNum)
{
	BYTE IdOutCmd[sizeof(SENDCMDOUTPARAMS)+IDENTIFY_BUFFER_SIZE - 1];
	bool bFlag = false;
	char driveName[32];
	HANDLE hDevice = 0;

	sprintf_s(driveName, 32, "\\\\.\\PhysicalDrive%d", driveNum);
	// 创建文件需要管理员权限
	hDevice = CreateFileA(driveName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice != INVALID_HANDLE_VALUE) {
		GETVERSIONOUTPARAMS versionParams;
		DWORD bytesReturned = 0;
		// 得到驱动器的IO控制器版本
		memset((void*)&versionParams, 0, sizeof(versionParams));
		if (DeviceIoControl(hDevice, SMART_GET_VERSION, NULL, 0,
			&versionParams, sizeof(versionParams), &bytesReturned, NULL))
		{
			if (versionParams.bIDEDeviceMap > 0) {
				BYTE bIDCmd = 0;   // IDE或者ATAPI识别命令
				SENDCMDINPARAMS scip;

				// 如果驱动器是光驱，采用命令IDE_ATAPI_IDENTIFY
				// 否则采用命令IDE_ATA_IDENTIFY读取驱动器信息
				bIDCmd = (versionParams.bIDEDeviceMap >> driveNum & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
				memset(&scip, 0, sizeof(scip));
				memset(IdOutCmd, 0, sizeof(IdOutCmd));
				// 为读取设备信息准备参数
				scip.cBufferSize = IDENTIFY_BUFFER_SIZE;
				scip.irDriveRegs.bFeaturesReg = 0;
				scip.irDriveRegs.bSectorCountReg = 1;
				scip.irDriveRegs.bSectorNumberReg = 1;
				scip.irDriveRegs.bCylLowReg = 0;
				scip.irDriveRegs.bCylHighReg = 0;
				// 计算驱动器位置
				scip.irDriveRegs.bDriveHeadReg = 0xA0 | (((BYTE)driveNum & 1) << 4);
				// 设置读取命令
				scip.irDriveRegs.bCommandReg = bIDCmd;
				scip.bDriveNumber = (BYTE)driveNum;
				scip.cBufferSize = IDENTIFY_BUFFER_SIZE;

				// 读取驱动器信息
				if (DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA,
					(LPVOID)&scip, sizeof(SENDCMDINPARAMS)-1, (LPVOID)&IdOutCmd,
					sizeof(SENDCMDOUTPARAMS)+IDENTIFY_BUFFER_SIZE - 1,
					&bytesReturned, NULL))
				{
					USHORT *pIdSector = (USHORT *)((PSENDCMDOUTPARAMS)IdOutCmd)->bBuffer;

					int nIndex = 0, nPosition = 0;
					char szSeq[32] = { 0 };
					for (nIndex = 10; nIndex < 20; nIndex++) {
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] / 256);
						nPosition++;
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] % 256);
						nPosition++;
					}
					serialNum = szSeq;
					serialNum.erase(0, serialNum.find_first_not_of(" "));
					bFlag = true;  // 读取硬盘信息成功
				}
				else
					std::cout << "DeviceIoControl error:" << GetLastError() << std::endl;
			}
			else
				std::cout << "bIDEDeviceMap <= 0" << std::endl;
		}
		else
			std::cout << "DeviceIoControl VERSION error:" << GetLastError() << std::endl;
		CloseHandle(hDevice);  // 关闭句柄
	}
	else
		std::cout << "CreateFileA error:" << GetLastError() << std::endl;
	return bFlag;
}

// 获取SCSI硬盘序列号(只支持Windows NT/2000/XP以上操作系统)
bool GetSCSIHDSerial(int driveNum, std::string& serialNum)
{
	bool bFlag = false;
	int controller = driveNum;
	HANDLE hDevice = 0;
	char driveName[32];
	sprintf_s(driveName, 32, "\\\\.\\Scsi%d:", controller);
	hDevice = CreateFileA(driveName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice != INVALID_HANDLE_VALUE) {
		DWORD dummy;
		for (int drive = 0; drive < 2; drive++) {
			char buffer[sizeof(SRB_IO_CONTROL)+SENDIDLENGTH];
			SRB_IO_CONTROL *p = (SRB_IO_CONTROL *)buffer;
			SENDCMDINPARAMS *pin = (SENDCMDINPARAMS *)(buffer + sizeof(SRB_IO_CONTROL));
			// 准备参数
			memset(buffer, 0, sizeof(buffer));
			p->HeaderLength = sizeof(SRB_IO_CONTROL);
			p->Timeout = 10000;
			p->Length = SENDIDLENGTH;
			p->ControlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;
			strncpy_s((char *)p->Signature, 9, "SCSIDISK", 9);
			pin->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
			pin->bDriveNumber = drive;
			// 得到SCSI硬盘信息
			if (DeviceIoControl(hDevice, IOCTL_SCSI_MINIPORT, buffer,
				sizeof(SRB_IO_CONTROL)+sizeof(SENDCMDINPARAMS)-1,
				buffer, sizeof(SRB_IO_CONTROL)+SENDIDLENGTH, &dummy, NULL))
			{
				SENDCMDOUTPARAMS *pOut = (SENDCMDOUTPARAMS *)(buffer + sizeof(SRB_IO_CONTROL));
				IDSECTOR *pId = (IDSECTOR *)(pOut->bBuffer);
				if (pId->sModelNumber[0]) {
					USHORT *pIdSector = (USHORT *)pId;
					int nIndex = 0, nPosition = 0;
					char szSeq[32] = { 0 };
					for (nIndex = 10; nIndex < 20; nIndex++) {
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] / 256);
						nPosition++;
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] % 256);
						nPosition++;
					}
					serialNum = szSeq;
					serialNum.erase(0, serialNum.find_first_not_of(" "));
					bFlag = true;  // 读取硬盘信息成功
					break;
				}
			}
		}
		CloseHandle(hDevice);  // 关闭句柄
	}
	return bFlag;
}

std::string GetCPUID()
{
	std::string strCPUId;
	unsigned long s1, s2;
	char buf[32] = { 0 };

	__asm{
		mov eax, 01h   //eax=1:取CPU序列号
			xor edx, edx
			cpuid
			mov s1, edx
			mov s2, eax
	}
	if (s1) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s1);
		strCPUId += buf;
	}
	if (s2) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s2);
		strCPUId += buf;
	}

	__asm{
		mov eax, 03h
			xor ecx, ecx
			xor edx, edx
			cpuid
			mov s1, edx
			mov s2, ecx
	}
	if (s1) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s1);
		strCPUId += buf;
	}
	if (s2) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s2);
		strCPUId += buf;
	}
	return strCPUId;
}

BOOL GetMacByCmd(char *lpszMac, int len/*=128*/)
{
	const long MAX_COMMAND_SIZE = 10000; //命令行输出缓冲大小      
	WCHAR szFetCmd[] = L"ipconfig /all"; //获取MAC命令行    
	const std::string strEnSearch = "Physical Address. . . . . . . . . : "; //网卡MAC地址的前导信息  
	const std::string strChSearch = "物理地址. . . . . . . . . . . . . : ";

	BOOL   bret = FALSE;
	HANDLE hReadPipe = NULL; //读取管道  
	HANDLE hWritePipe = NULL; //写入管道      
	PROCESS_INFORMATION pi;   //进程信息      
	STARTUPINFO         si;   //控制命令行窗口信息  
	SECURITY_ATTRIBUTES sa;   //安全属性  

	char            szBuffer[MAX_COMMAND_SIZE + 1] = { 0 }; //放置命令行结果的输出缓冲区  
	std::string          strBuffer;
	unsigned long   count = 0;
	long            ipos = 0;

	pi.hProcess = NULL;
	pi.hThread = NULL;
	si.cb = sizeof(STARTUPINFO);
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	//1.0 创建管道  
	bret = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
	if (!bret)
	{
		goto END;
	}

	//2.0 设置命令行窗口的信息为指定的读写管道  
	GetStartupInfo(&si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.wShowWindow = SW_HIDE; //隐藏命令行窗口  
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	//3.0 创建获取命令行的进程  
	bret = CreateProcess(NULL, szFetCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!bret)
	{
		goto END;
	}

	//4.0 读取返回的数据  
	WaitForSingleObject(pi.hProcess, 2000/*INFINITE*/);
	bret = ReadFile(hReadPipe, szBuffer, MAX_COMMAND_SIZE, &count, 0);
	if (!bret)
	{
		goto END;
	}

	//5.0 查找MAC地址，默认查找第一个,一般为以太网的MAC  
	strBuffer = szBuffer;
	ipos = strBuffer.find(strEnSearch);

	if (ipos < 0)//区分中英文的系统  
	{
		ipos = strBuffer.find(strChSearch);
		if (ipos < 1)
		{
			goto END;
		}
		//提取MAC地址串  
		strBuffer = strBuffer.substr(ipos + strChSearch.length());
	}
	else
	{
		//提取MAC地址串  
		strBuffer = strBuffer.substr(ipos + strEnSearch.length());
	}

	ipos = strBuffer.find("\n");
	strBuffer = strBuffer.substr(0, ipos);

	memset(szBuffer, 0x00, sizeof(szBuffer));
	strcpy_s(szBuffer, strBuffer.c_str());

	//去掉中间的“00-50-EB-0F-27-82”中间的'-'得到0050EB0F2782  
	int j = 0;
	for (int i = 0; i<strlen(szBuffer); i++)
	{
		if (szBuffer[i] != '-')
		{
			lpszMac[j] = szBuffer[i];
			j++;
		}
	}

	bret = TRUE;

END:
	//关闭所有的句柄  
	CloseHandle(hWritePipe);
	CloseHandle(hReadPipe);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return(bret);
}

#endif


int getcpuid(char *cpu_id, int size)
{
#ifdef WIN32
	sprintf(cpu_id, "%s", GetCPUID().c_str());
	return 0;

#else
	unsigned long s1, s2, s3, s4;
	char string[128];
	char szCpuId[1024];
	char p1[128], p2[128];
	unsigned int eax = 0;
	unsigned int ebx, ecx, edx;

	asm volatile
	(
		"cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "0"(0)
	);
	snprintf(szCpuId, 5, "%s", (char *)&ebx);
	snprintf(szCpuId + 4, 5, "%s", (char *)&edx);
	snprintf(szCpuId + 8, 5, "%s", (char *)&ecx);

	asm volatile
	(
		"movl $0x01 , %%eax ; \n\t"
		"xorl %%edx , %%edx ;\n\t"
		"cpuid ;\n\t"
		"movl %%edx ,%0 ;\n\t"
		"movl %%eax ,%1 ; \n\t"
		:"=m"(s1), "=m"(s2)
	);

	sprintf((char *)p1, "-%08X\n%08X-", s1, s2);
	snprintf(szCpuId + 12, 20, "%s", (char *)p1);

	asm volatile
	(
		"movl $0x03,%%eax ;\n\t"
		"xorl %%ecx,%%ecx ;\n\t"
		"xorl %%edx,%%edx ;\n\t"
		"cpuid ;\n\t"
		"movl %%edx,%0 ;\n\t"
		"movl %%ecx,%1 ;\n\t"
		:"=m"(s3), "=m"(s4)
	);

	sprintf((char *)p2, "%08X-%08X\n", s3, s4);
	snprintf(szCpuId + 31, 19, "%s", (char *)p2);

	strcpy(cpu_id, szCpuId);
	return 0;
#endif
}

int getdiskid(char *disk_id, int size)
{
#ifdef WIN32
	std::string serialNum;
	for (int driveNum = 0; driveNum < 5; driveNum++) {
		if(!GetIDEHDSerial(driveNum, serialNum))
			GetSCSIHDSerial(driveNum, serialNum);
		if (!serialNum.empty())
			break;
	}
	sprintf(disk_id, "%s", serialNum.c_str());
	return 0;
#elif __APPLE__

#else
	int fd;
    struct hd_driveid hid;
	fd = open("/dev/sda", O_RDONLY);
	if (fd < 0)
	{
		return -1;
	}
    if (ioctl(fd, HDIO_GET_IDENTITY, &hid) < 0)
    {
        perror("get disk id err:");
        close(fd);
        return -1;
    }
	close(fd);
    sprintf(disk_id, "%s", hid.serial_no);
	return 0;
#endif
}

int getmacaddr(char *mac_addr, int size)
{
#ifdef WIN32
	char lpszMac[128] = { 0 };
	GetMacByCmd(lpszMac, 128);
	sprintf(mac_addr, "%s", lpszMac);
	return 0;
#elif __APPLE__

#else
	int sock_mac;

	struct ifreq ifr_mac;

	sock_mac = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_mac == -1)
	{
		perror("create socket failed...mac\n");
		return -1;
	}

	memset(&ifr_mac, 0, sizeof(ifr_mac));
	strncpy(ifr_mac.ifr_name, "eth0", sizeof(ifr_mac.ifr_name) - 1);

	if ((ioctl(sock_mac, SIOCGIFHWADDR, &ifr_mac)) < 0)
	{
		//perror("mac ioctl error:");
		close(sock_mac);
		return -1;
	}

	sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char)ifr_mac.ifr_hwaddr.sa_data[0],
		(unsigned char)ifr_mac.ifr_hwaddr.sa_data[1],
		(unsigned char)ifr_mac.ifr_hwaddr.sa_data[2],
		(unsigned char)ifr_mac.ifr_hwaddr.sa_data[3],
		(unsigned char)ifr_mac.ifr_hwaddr.sa_data[4],
		(unsigned char)ifr_mac.ifr_hwaddr.sa_data[5]);
	close(sock_mac);
	return  0;
#endif
}

#ifdef __APPLE__
#include <IOKit/IOKitLib.h>
void get_platform_uuid(char * buf, int bufSize)
{
   io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
   CFStringRef uuidCf = (CFStringRef) IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
   IOObjectRelease(ioRegistryRoot);
   CFStringGetCString(uuidCf, buf, bufSize, kCFStringEncodingMacRoman);
   CFRelease(uuidCf);
}
#endif

int getdeviceuuid(char *device_uuid, int size)
{
#ifdef __APPLE__
    get_platform_uuid(device_uuid, size);
#else
	char cpu_id[64] = "\0";
	char disk_id[64] = "\0";
	char mac_addr[32] = "\0";
	char data[128];
	getcpuid(cpu_id, sizeof(cpu_id));
	getdiskid(disk_id, sizeof(disk_id));
	getmacaddr(mac_addr, sizeof(mac_addr));
	//printf("cpu_id: %s\n", cpu_id);
	//printf("disk_id: %s\n", disk_id);
	//printf("mac_addr: %s\n", mac_addr);
	snprintf(data, sizeof(data), "%s:%s:%s", cpu_id, disk_id, mac_addr);
	unsigned char md[16];
	int i;
	char tmp[3] = { '\0' };
	char buf[33] = { '\0' };
	MD5((const unsigned char *)data, strlen(data), md);
	for (i = 0; i < 16; ++i)
	{
		sprintf(tmp, "%2.2x", md[i]);
		strcat(buf, tmp);
	}
	strncpy(device_uuid, buf, size);
	//printf("device_uuid: %s\n", device_uuid);
#endif
	return 0;
}

#if 0
int main(void)
{
	char device_uuid[256];
	getdeviceuuid(device_uuid, sizeof(device_uuid));
	printf("device_uuid: %s\n", device_uuid);
	getchar();
	return 0;
}
#endif
