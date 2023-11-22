#ifndef __WDS_LIST_ALL__
#define __WDS_LIST_ALL__

#define DEBUG_LOG_SIZE				4000         		/* log file size : 4k*/
#define DEBUG_LOG_LINE_SIZE 		1000		  		/* Row size of the log file : 1k*/

#define SUCCESS						0
#define FAIL						-1

#define MODULE_NAME 				"wds_list_all"

#define PBUF_SIZE    				200*1024


#define STR_MAC_SIZE     			18
#define WDS_PW_INFO_ARR_LEN     	5

struct wds_info {
    unsigned long time_update;
    unsigned char sn[30];
    unsigned char peer_sn[30];
    unsigned char sys_mac[20];
    unsigned char ath_mac[20];
    unsigned char peermac[20];
    char dev_type[20];
	unsigned char ipaddr[20];
    unsigned char netmask[20];
    unsigned char time[20];
    unsigned char band[7];
    unsigned char rssi[7];
    unsigned char rssi_a[7];
    unsigned char rate[7];
    unsigned char channel[5];
    unsigned char passwd[100];
    unsigned char channf[10];
    unsigned char chutil[10];
    unsigned char chutil_a[10];
    unsigned char phymode[50];

	char host_name[65];
    char role[10];
    char lock[10];
    char onlinestatus[10];
    char cwmp[5];
    char lan1speed[15];
    char lan1link[15];
    char lan1duplex[15];
	char lan1nosupport[10];
    char lan2speed[15];
    char lan2link[15];
    char lan2duplex[15];
	char lan2nosupport[10];
    //实时流量
    char rx_rate[15];
    char tx_rate[15];

    //实时协商速率
    char rx_speed[10];
    char tx_speed[10];
    //平均协商速率
    char rx_speed_a[10];
    char tx_speed_a[10];

    char ssid[33];
    char software_version[60];
	char softver_new[20];
	char clean_sftn[2]; 				//Used to clear residual "ReyeeOS" in "softver_new"
    char hardware_version[40];

	char wds_tpye[20];
    char wds_distance[10];
    char wds_txpower[10];
    int nf;                       		//底噪
    int channel_use;             		//信道利用�?
    char pingTime[15];
    char connectTime[20];
    char networkid[33];
    char networkname[65];
	char country[4];
    char flag;
    unsigned char dfs_ch;      			//dfs上次退避的信道
    char dfs_time[20];         			//dfs上次触发的时�?
    char def_pw[10];           			//是否是默认桥接密�?
    char wds_pw[10];           			//是否支持设置桥接密码
    char wdspw_state[5];      			//来关联设备的桥接密码是否错误
    char warn_mac[110];         		//关联本设备的桥接密码错误的设�?
	char scan_dev_cap[10];    			//是否支持扫描设备和被扫描
	char scan_pw_state[5];      		//ap使用扫描设备时输入的cpe的密码是否正�?
    char scan_warn_mac[(STR_MAC_SIZE-1)*WDS_PW_INFO_ARR_LEN+(WDS_PW_INFO_ARR_LEN-1)+1];	//ap使用扫描设备时输入的cpe的密码，密码错误的cpe的mac
    char manage_ssid[65];      			//管理ssid
    char manage_bssid[20];      		//管理bssid
    char dc_power[10];           		//是否支持dc供电
    char poe_power[10];          	    //是否支持poe供电
    char distance_max[10];
	char distance_def[10];
	char automatic_range[5];
	char wan_speed_cap[5];				//有线接口最大速率(1000M/100M)
	char rssi_align[5];	
};

typedef struct {
	struct wds_info wds_info;
	struct list_head wla_head;
} wds_list_all_t;

#endif


