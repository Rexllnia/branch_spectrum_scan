#ifndef __wdslinkquality__
#define __wdslinkquality__

#define DEBUG_LOG_SIZE				4000         		/* log file size : 4k*/
#define DEBUG_LOG_LINE_SIZE 		1000		  		/* Row size of the log file : 1k*/
#define MODULE_NAME 				"wdsLinkQuality"
#define FAIL 						-1
#define SUCCESS						0

#define ROLE_IS_AP         			"ap"
#define ROLE_IS_CPE        			"cpe"


#define STR_MAC_SIZE     			18
#define WDS_PW_INFO_ARR_LEN     	5

#define UCI_SYSINFO_FILE   			"/etc/config/sysinfo"
#define PBUF_SIZE    				16*1024

struct wds_info {
    unsigned char sn[30];
    unsigned char peer_sn[30];
    unsigned char sys_mac[20];
    unsigned char ath_mac[20];
    unsigned char peermac[20];
    unsigned char channf[10];
    unsigned char chutil[10];
    char role[10];
    char pingTime[15];
};

struct rssi_info {
    char uplink_rssi_h;
    char uplink_rssi_v;
    char downlink_rssi_h;
    char downlink_rssi_v;
};

typedef struct {
	struct wds_info wds_info;
    struct rssi_info rssi_info;
	struct list_head wlq_head;
}wds_link_qua_t;

#endif



















