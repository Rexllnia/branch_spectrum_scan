#include <sys/types.h>
#include <linux/types.h>
#include <ctype.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <time.h>
#include <stdio.h>
#include <linux/sysinfo.h>
#include <time.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <uci.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <linux/wireless.h>
#include <err.h>
#include <netinet/udp.h>
#include <json.h>
#include <signal.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <libubox/uloop.h>

#include "librg_crypto.h"
#include "rg_wds_protocl.h"
#include "rg_wds_beacon.h"
#include "rg_wds_json.h"
#include "rg_wds_recv_massage.h"
#include "rg_wds_pair_all.h"
#include "wds_gpio_debug.h"
#include "automatic_range.h"

#include <syslog.h>

#include "wds_pw_state.h"
//#include <cJSON.h>


#define MODE_AP         1
#define MODE_CPE        0
#define MODE_UNKNOW    0xff

#define LOCK            1
#define UNLOCK          0

#define UCI_ATTRI_OPTION 0
#define UCI_ATTRI_LIST 1

#define WDS_OFF "OFF"
#define WDS_ON "ON"
#define WDS_OTHER "UNKNOW"


#define MODE_VALUE_AP         "ap"
#define MODE_VALUE_CPE        "sta"
#define DEF_SSID 			  "@Ruijie-wds"

#define MODE_GPIO       2
#define LOCK_GPIO       3

#define SUCESS    0
#define FAIL     -1

#define WDS_LED_TIMEOUT 7200

#define MAC_LEN 17

#define UCI_CONFIG_FILE "/etc/config/wireless"

#define WDS_CLIENT_SYNC 0
#define WDS_CLIENT_ACK  1

#define REBOOT_TIME 60*5
#define SEND_TIME 20

#define SN_MAC_INIT 0     // 第一次初始化
#define SN_MAC_UPDATE 1   // 更新hostname信息
#define SN_MAC_ADD 2      //  添加新的设备
#define SN_MAC_DELET 3      // 设备的锁和模式发生变化

#define WDS_DOWN_TIME 20

#define DEV_FILE_MODEL                               "/proc/rg_sys/model"
#define DEV_FILE_SYSMAC                             "/proc/rg_sys/sys_mac"
#define DEV_FILE_SN                                      "/proc/rg_sys/serial_num"
#define DEV_FILE_HARDWARE_VERSION       "/proc/rg_sys/hardware_version"
#define DEV_FILE_SOFTWARE_VERSION        "/etc/openwrt_version"
#define WDS_GETSN_CMD                            "cat /proc/rg_sys/serial_num"
#define WDS_DF_PW_FILE                             "/etc/rg_config/wds_df_password"
#define WDS_DF_PW                             "est@wds#mjkf997!"

#define DEV_301        "EST301"
#define DEV_302        "EST302"

#define ATH_MODE_STA                  "1" 
#define ATH_MODE_AP                   "0" 

#define DFS_FILE_PATH                    "/proc/est/dfs_radar"

#define NETWORKID_FILE_PATH      "/tmp/rg_config/tmp_nid_flag" 

#define DFS_JSON_PATH                  "/etc/rg_config/dfs_json"

#define CMD_GET_CHANNEL 		"wireless.%s.channel"
#define EWEB_PW_FILE       		"/etc/rg_config/admin"
#define EWEB_DEF_PW_DC 			"admin"
#define EWEB_DEF_PW 			"U2FsdGVkX1/tV9LOvYktw6g4bq+wzr5TEtX9/cAMwXc="

#define MAC_TAB_SIZE  				6000 
#define CMD_GET_CHAN_FLOORNOISE      "wlanconfig %s %s | grep floornoise | awk -F ':' '{print $2}'"
#define CMD_GET_CHAN_UTIL            "wlanconfig %s %s | grep utilization | awk -F ':' '{print $2}'"
#define CMD_GET_RXFLOW               "wlanconfig %s %s | grep rxflow | awk -F ':' '{print $2}'"
#define CMD_GET_TXFLOW               "wlanconfig %s %s | grep txflow | awk -F ':' '{print $2}'"
#define CMD_GET_NETWORKCONNECT        "dev_sta get -m networkConnect|jq .connnected -r"
#define CMD_CPE_GET_PEERSN                  "/tmp/wds_info.json"
#define CMD_GET_WDS_DF_PW                  "wireless.%s.%s"
#define CMD_GET_UCI_WDS_FMT				CMD_GET_WDS_DF_PW
#define CMD_GET_MANAGE_SSID         "wireless.%s.ssid"      //"iwconfig %s | grep ESSID | awk -F ':' '{print $2}'"
#define CMD_GET_MANAGE_BSSID         "ifconfig %s | grep HWaddr | awk -F 'HWaddr ' '{print $2}'"
#define CMD_GET_COUNTYCODE          "wireless.%s.country"

#define LOOK_UNLOOK_EVENT       0x1
#define UNLOOK_LOOK_EVENT       0x2
#define AP_STA_EVENT             0x4
#define STA_AP_EVENT             0x8
#define STA_AP_EVENT_BIT         3

//没有从wlanconfig list 获取到对应的mac的设备超过这个时间
#define WLANCONFIG_LIST_OFF_TIME 30

//CPE 链路不通情况下10分钟重启wifi，1小时重启设备
//ROOT 链路不通，且没有其他cpe情况下，20分钟重启wifi，2小时重启设备
#define WDS_KEEP_WIFI_RELOAD 10*60
#define WDS_KEEP_WIFI_REBOOT 6
#define WDS_FAST_FLAG_KEEP_LIVE   12*2

/* 定义网络报文头部宏 */
#define WDS_ETH_HEAD_LEN        14
#define WDS_IP_HEAD_LEN         20
#define WDS_UDP_HEAD_LEN        8
#define WDS_PSEUDO_HEAD_LEN     12

#define WDS_KEEP_WIFI_ROOT_RELOAD 20*60
#define WDS_KEEP_WIFI_ROOT_REBOOT 6
#define MAC2STR "%02X:%02X:%02X:%02X:%02X:%02X"
#define PRINT_MAC(addr)        \
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
#define MAC_FORMAT "%02X %02X %02X %02X %02X %02X"

#define DEBUG_ERROR(fmt,args...)                                                           \
{                                                                                          \
	printf("[%s]:[%d] "#fmt"\n",__func__,__LINE__,##args);           \
}

//软件版本相关
#define SOFT_VERSION_FILE  "/tmp/wds_softversion.json"
//软件版本相关

char reload_wifi_count;
unsigned long last_data_time;

//设备当前的radio类型
enum{
    MNG_2G_WDS_2G = 0, //管理2.4G和桥接2.4G
    MNG_5G_WDS_5G = 1, //管理5G和桥接5G      
    MNG_2G_WDS_5G = 2, //管理2.4G和桥接5G
};

/* 表示一台设备的信息，与桥接无关 */
struct dev_info {
	char dev_type[20]; //EST310_V2
	unsigned char sys_mac[6];
	char sn[30];
	unsigned int ip;
	char host_name[65];
	char hardware_version[10];
    char software_version[55];
};

//ath 接口 相关信息，mac地址名称等等,包含其他的该ath口的一些配置信息，都认为和ath相关
struct dev_multi_info {
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
	char clean_sftn[2]; //Used to clear residual "ReyeeOS" in "softver_new"
    char hardware_version[40];

	char wds_tpye[20];
    char wds_distance[10];
    char wds_txpower[10];
    int nf;                       //底噪
    int channel_use;             //信道利用率
    char pingTime[15];
    char connectTime[20];
    char networkid[33];
    char networkname[65];
	char country[4];
    char flag;
    unsigned char dfs_ch;      //dfs上次退避的信道
    char dfs_time[20];         //dfs上次触发的时间
    char def_pw[10];           //是否是默认桥接密码
    char wds_pw[10];           //是否支持设置桥接密码
    char wdspw_state[5];      //来关联设备的桥接密码是否错误
    char warn_mac[110];         //关联本设备的桥接密码错误的设备
	char scan_dev_cap[10];    //是否支持扫描设备和被扫描
	char scan_pw_state[5];      //ap使用扫描设备时输入的cpe的密码是否正确
    char scan_warn_mac[(STR_MAC_SIZE-1)*WDS_PW_INFO_ARR_LEN+(WDS_PW_INFO_ARR_LEN-1)+1];	//ap使用扫描设备时输入的cpe的密码，密码错误的cpe的mac
    char manage_ssid[65];      //管理ssid
    char manage_bssid[20];      //管理bssid
    char dc_power[10];           //是否支持dc供电
    char poe_power[10];           //是否支持poe供电
    char distance_max[10];
	char distance_def[10];
	char automatic_range[5];
	char wan_speed_cap[5];//有线接口最大速率(1000M/100M)
	char rssi_align[5];
    struct dev_multi_info *next;
};

//ath 接口 相关信息，mac地址名称等等,包含其他的该ath口的一些配置信息，都认为和ath相关
struct ath_info {
	unsigned char ath_wds_name[20];    //桥接口
	unsigned char ath_managed_name[20];//管理口
	unsigned char ath_mac[17];
	unsigned char root_mac_hex[6];
	char role;
	char ssid[33];
	char bssid[6];                  //是否配置了BSSID   0表示没有  1 表示有
	char option_macfilter;                 // 是否配置了白名单 0表示没有  1 表示有
	char list_maclist;
	char wds_tpye[20];
    char wds_distance[10];
    char wds_txpower[10];
    int nf;                       //底噪
    int channel_use;             //信道利用率
};

//ath 接口 相关信息，mac地址名称等等
struct assioc_info {
	int rssi;
	int rxrate;
	int txrate;
    int channel;
    unsigned int assioc_time;
    unsigned char BW;
};

//对端关联信息
struct pair_keep_time {
	unsigned long pair_live_get_num;    //接受保活报文的个数
	unsigned long pair_live_send_num;   //发送保活报文的个数
	unsigned long pair_live_get_time;   //收到保活报文的时间
};

struct gpio_info {
	char gpio_mode_num; //2
	char gpio_mode_value;
	char gpio_mode_value_last;
	char gpio_lock_num; //3
	char gpio_lock_value;
	char gpio_lock_value_last;
	char gpio_event;
};

//对端关联信息，AP端会有对个存在，CPE只有一个，始终维持一个
//cpe端该信息由wlanconfig 指令获取，ap端由保活信息获取
struct pair_dev_ath_info {
	unsigned char mac[6];               //唯一的标识
	unsigned long time_newest;//收到的该设备的最新的时间，只能是外部触发更新
	char maclist_flag;
	char version_flag;          //0旧版本，1新版本
	char lock_flag;
	struct pair_keep_time pair_keep_info_t;
	struct dev_info pair_dev_info_t;
	struct assioc_info pair_assioc_info_t;
	struct gpio_info lock_info_t;
	struct pair_dev_ath_info *next;
};

struct cpe_list {
	unsigned char receve_status;
	unsigned long receve_timeout;
	unsigned char cpe_mac[6];
	struct cpe_list *next;
};

/* 底层获取的自身和对端的rssi实时信息结构体，只用于存储到redis */
struct redis_rssi_info {
	unsigned char mac[6];
    char uplink_rssi_h;
    char uplink_rssi_v;
    char downlink_rssi_h;
    char downlink_rssi_v;
};

#define MTU_SIZE 1600 
#define RINGBUF_MAX 64
#define THREAD_POOL_SIZE 2
#define MAX_TASKS 2

typedef struct {
    char* buffer[RINGBUF_MAX];
    int head;
    int tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} RingBuffer;

typedef struct {
    pthread_t thread;
    void* (*function)(void*);
    void *arg;
} pool_task_t;

typedef struct {
    pool_task_t *tasks[MAX_TASKS];
    int count;
    int head;
    int tail;
    pthread_t threads[THREAD_POOL_SIZE];
    pthread_mutex_t mutex;
    pthread_cond_t cond_not_empty;
    pthread_cond_t cond_not_full;
} thread_pool;

typedef struct {
    RingBuffer* ringbuf;
    thread_pool* pool;
} thread_args;

#define  DEV_CAP_DIR   		"/tmp/rg_device/rg_device.json"
#define  PEER_WDS_INFO 		"/tmp/wds_info.json"
#define  AP_SN                       "/tmp/.ap_sn"

//device capacity table(More will follow)
#define SWITCH_PORT_LENGTH   5
struct  dev_capacity_table{
    char dev_name[6]; //eth0
    char switch_num;
    char switch_name[15]; //switch0
    char switch_port[SWITCH_PORT_LENGTH];
    char wifi_name[10]; //MT7628_1
	char support_ra[6];
	char wds_pw[10];
	int radio; //0是2.4G，1是5G
	char wds_ifname[6];
	char mag_ifname[6];
    char wds_cpe_ifname[15];
    int dc_power;
    int poe_power;
	int distance_max;
	int distance_def;
	int automatic_range;
	int wan_speed; //wired port max rate(1000M/100M).
	int rssi_align;
	char scan_dev_cap[8]; //R228
};
#define MAC_SIZE    6

extern struct dev_info rg_dev_info_t;
extern struct ath_info rg_ath_info_t;
//不一定有对端信息，因此用指针表示
extern struct pair_dev_ath_info *rg_pair_info_heap_t;
extern struct gpio_info rg_gpio_info_t;
extern pthread_mutex_t rg_pair_mtx;
extern pthread_mutex_t mtx_wds_beacon_list;
extern pthread_mutex_t mtx_scan_dev_list;
extern pthread_mutex_t mtx_wds_softversion_file;
extern pthread_mutex_t wds_fast_pair_mtx;
extern struct  dev_capacity_table rg_dev_capacity_table;
extern struct uloop_timeout wds_gpio_timeout;

int rg_wds_check_udp_checksum(char *pkt);
int rg_cpe_check_setssid_condition(char *pkt);
int rg_wds_check_all_packet_validity(char *pkt);
int undefault_ssid_lock_status(int ap_mode, char *wds_ssid, char *maclist, char *bssid);
char wds_sn_mac_create_file_all(char flag);
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
int get_bssid_list(char *bssid_list) ;
void wds_sn_mac_clear_date();
int send_raw_date(char *ifname,unsigned int src_port,unsigned int dec_port,int led,unsigned char *send_msg,char *dst_char_mac);
void cpe_ap_sync_unlock_led(char cpe_count,char action);
void dump_date(unsigned char *buf,int len);
char wds_sn_mac_update_info_pair_from_cpe(struct wds_sn_mac_hostname *str);
int wds_send_keep_date(char *dst_mac);
char wds_sn_mac_update_info_pair_from_cpe(struct wds_sn_mac_hostname *str);
char rg_wds_dev_init(struct dev_info *dev_info_t);
u_int32_t rg_wds_misc_get_iface_ip_str(int ip,char *buf,char len);
char rg_wds_ath_init(struct dev_info *dev_info_t,struct ath_info *ath_info_t);
void rg_wds_sysled_control(void);
void rg_wds_send_sync_led_date(struct pair_dev_ath_info * p,char atcion);
int rg_send_raw_date(char *ifname,int data_len,unsigned char *send_msg,char *dst_char_mac);
void ringbuffer_pkt_recv_pthread(void *arg);
void ringbuffer_pkt_handle_pthread(void *arg);
void broadcast_pkt_send_pthread(void);
int ringbuffer_init(RingBuffer *ringbuf);
int rg_wds_pair_list_stations(const char *ifname);
void rg_wds_keep_data_respone();
char rg_wds_pair_all_offline();
int rg_wds_ath_reload_wifi();
void rg_wds_pair_list_update();
void rg_wds_dev_update(struct dev_info *dev_info_t);
char rg_wds_pair_offline(struct pair_dev_ath_info * p);
void rg_wds_get_system_info_ap(char *data);
void rg_wds_send_cpe_info();
void rg_wds_sysinfo_write_ap();
char rg_wds_pair_list_len();
void rg_wds_send_ap_info();
void rg_wds_get_system_info_cpe(char *data);
void rg_wds_get_keep_date(char *data,int len);
void rg_wds_beacon_show();
int rg_wds_send_date_head_init(struct  mac_ip_udp_wds_packet *eth_packet_heap_p);
void rg_wds_version_get(char *data,int len);
void rg_wds_version_send_ap();
void rg_wds_version_send_cpe();
char rg_wds_version_cpe_check();
char rg_wds_ath_set_ssid(char *ssid);
char rg_wds_ath_update(struct ath_info *ath_info_t);
void wds_list_time_update();
void delete_overtime_scan_dev_node();
void update_beacon_info();
void bcn_expand_info_switch(int connet_stat);
char scan_dev_list_to_file();
void rg_wds_beacon_join_net_cpe();
void rg_wds_beacon_join_net_ap();
void rg_wds_lock_status_update(char *data);
void rg_wds_ap_add_maclist();
unsigned char switch_mac_char_2_hex(char *src_char_mac,unsigned char *dst_mac);
char rg_wds_ath_bssid_check();
char rg_wds_list_scanner();
void rg_wds_sysinfo_update_cpe();
char  rg_wds_misc_exe_shell_cmd(char *cmd,char *buf,char len);
char rg_wds_first_set(char *file_name, char *first_option, char *buf);
char rg_wds_second_set(char *file_name,char *first_option,char *second_option,char *buf);
int rg_wds_misc_clear_file(char * file_name);
void rg_wds_soft_version_cpe_send();
void rg_wds_soft_version_ap_send();
void rg_wds_get_softversion(unsigned char *packet,int len);
int rg_wds_udp_recv_init();
int rg_wds_udp_process();
void rg_wds_ap_update_process();
void rg_wds_version_wds_date_head_fill(struct wds_date_head *version_date_p,char flag);
void rg_wds_get_update_cmd(unsigned char * packet,int len);
char rg_wds_wifi_get_txpower(struct ath_info *ath_info_t);
char * rg_wds_cmp_str(char *src,char *dest);
void rg_wds_message_dev_process(char *str,bool b_self);
void rg_wds_write_info_all_list();
char rg_wds_misc_cmd(char *cmd,char *buf,char len);
char rg_wds_wifi_get_txpower(struct ath_info *ath_info_t);
u_int32_t rg_wds_misc_get_iface_netmask(char *ifname,char *buf);
void rg_wds_sw_status_status(char *name,char port,char *link,char *speed,char *duplex);
void rg_wds_uci_get_param(char *uci_param, char *buff, int len);
bool rg_wds_dfs_test_flag(void);
bool rg_wds_func_test_flag(void);
bool is_dfs_file_exist(void);
bool is_dfs_json_exist(void);
void get_trigger_dfs_channel_time(void);
int dev_capacity_init(struct  dev_capacity_table* rg_dev_capacity_t);
void wds_gpio_run(void);
int dfs_uci_switch_status(char * status);
char * ReadFile(char * path, int *length);
bool is_arry_all_zero(char* arry, int len);
#ifdef EST_SUPPORT_REDIS
int rg_wds_redis_sub_thread(void);
#endif
