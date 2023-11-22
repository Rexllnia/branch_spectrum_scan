#ifndef __SCAN_AP__
#define __SCAN_AP__

#include <linux/wireless.h>

#if WIRELESS_EXT <= 11
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE						0x8BE0
#endif
#define SIOCIWFIRSTPRIV						SIOCDEVPRIVATE
#endif

#define RTPRIV_IOCTL_SET					(SIOCIWFIRSTPRIV + 0x02)

#define RTPRIV_IOCTL_GSITESURVEY			(SIOCIWFIRSTPRIV + 0x0D)

#define MODULE_NAEM							"scan_ap"
#define DATA_BUF_SIZE						100*1024
#define PBUF_SIZE							32*1024

#define SET_SCAN_AP_CMD						"PartialScan=1"
#define GET_SCAN_AP_CMD						""
#define DEVICE_INFO_FILE 					"/tmp/rg_device/rg_device.json"

#define WDS_BSS_BUF							32
#define CMD_BUF_SIZE						256

#define DEBUG_LOG_FILE_SIZE					4000			
#define DEBUG_LOG_LINE_SZIE					1000

#endif

