#ifndef __SCAN_WDS_AP__
#define __SCAN_WDS_AP__

#include <linux/wireless.h>

#if WIRELESS_EXT <= 11
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE						0x8BE0
#endif
#define SIOCIWFIRSTPRIV						SIOCDEVPRIVATE
#endif

#define RTPRIV_IOCTL_SET					(SIOCIWFIRSTPRIV + 0x02)

#define MODULE_NAEM							"scan_wds_ap"

#define DEBUG_LOG_FILE_SIZE					4000			
#define DEBUG_LOG_LINE_SZIE					1000

#define SET_PARTIAL_SCAN_CMD 				"PartialScan=1"

#define PBUF_SIZE							10*1024

#endif

