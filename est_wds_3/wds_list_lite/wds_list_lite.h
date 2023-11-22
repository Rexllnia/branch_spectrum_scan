#ifndef __WDS_INFO_LITE__
#define __WDS_INFO_LITE__

#define DEBUG_LOG_SIZE				4000         		/* log file size : 4k*/
#define DEBUG_LOG_LINE_SIZE 		1000		  		/* Row size of the log file : 1k*/

#define SUCCESS						0
#define FAIL						-1

#define MODULE_NAME 				"wds_list_lite"

#define PBUF_SIZE    				64*1024


#define STR_MAC_SIZE     			18
#define WDS_PW_INFO_ARR_LEN     	5

struct wds_info {
    unsigned char sn[30];
    unsigned char sys_mac[20];
    unsigned char ath_mac[20];
    unsigned char peermac[20];
    char dev_type[20];
    unsigned char rssi[7];
    unsigned char channel[5];
	char host_name[65];
    char role[10];

    //实时协商速率
    char rx_speed[10];
    char tx_speed[10];
    char connectTime[20];
    char networkid[33];
    char networkname[65];
    char flag;
    char def_pw[10];           	//是否是默认桥接密�?
    char wds_pw[10];           	//是否支持设置桥接密码
    char wdspw_state[5];     	//来关联设备的桥接密码是否错误
    char warn_mac[110];    		//关联本设备的桥接密码错误的设�?
    char manage_ssid[65];  		//管理ssid
    char manage_bssid[20]; 		//管理bssid
    char dc_power[10];   		//是否支持dc供电
    char poe_power[10];   	    //是否支持poe供电
	char rssi_align[5];
};

typedef struct {
	struct wds_info wds_info;
	struct list_head wil_head;
} wds_info_lite_t;



#endif


