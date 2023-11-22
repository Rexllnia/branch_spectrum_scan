#ifndef _ONE_CLICK_CONN_H
#define _ONE_CLICK_CONN_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <json-c/json.h>
#include <uci.h>
#include "uf_plugin_intf.h"
#include "lib_unifyframe.h"
#include "was_sdk.h"
#include "librg_crypto.h"
#include "one_click_log.h"

#if WIRELESS_EXT <= 11
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE 0x8BE0
#endif
#define SIOCIWFIRSTPRIV SIOCDEVPRIVATE
#endif
#define RT_PRIV_IOCTL (SIOCIWFIRSTPRIV + 0x01)
#define RTPRIV_IOCTL_SET (SIOCIWFIRSTPRIV + 0x02)


#define DEVICE_INFO_FILE "/tmp/rg_device/rg_device.json"
#define UCI_CONFIG_FILE "/etc/config/wireless"
#define ONE_CC_LOG_FILE "/tmp/OneClickConn/one_click_conn.log"
#define MAX_BUF_SIZE 1024
#define ONE_CC_LOG_FILE_SIZE                   20

#define OCC_LOW_TXPOWER 10

#define FAIL 1
#define SUCCESS 0

#define AP 1
#define STA 0

#define GET_UCI_SUCCESS 0
#define GET_UCI_ERR 1
#define UCI_SECTION_NULL 2

#define LED_SEND_MESSAGE(x) "/sbin/led_send_message \""x"\""

#define OCC_LED_SWITCH "mesh;switch"
#define OCC_LED_ON "mesh;found"
#define OCC_LED_OFF "mesh;default"

#define MAC_TAB_LEN  6000    //sizeof(RJ80211_MAC_TABLE)+sizeof(rj_stainfo_t)
//			16 			   +     152        *    32(cpe)  = 4880 < 5120



#endif // !_ONE_CLICK_CONN_H