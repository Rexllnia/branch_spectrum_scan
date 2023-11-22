#ifndef _Default_Config_H_
#define _Default_Config_H_

#define DF_DEBUG(format, ...) do {\
    UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\
} while(0)

#define DEVICE_INFO_FILE "/tmp/rg_device/rg_device.json"
#define MAX_BUF_SIZE 1024
#define MAX_LEN_OF_SSID 32

#define SUCCESS 1
#define FAIL 0

#define AP 1
#define STA 0

#endif /* _Default_Config_H_ */