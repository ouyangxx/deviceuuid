#ifndef __DEVICE_UUID__
#define __DEVICE_UUID__

int getcpuid(char *cpu_id, int size);

int getdiskid(char *disk_id, int size);

int getmacaddr(char *mac_addr, int size);

int getdeviceuuid(char *device_uuid, int size);

#endif