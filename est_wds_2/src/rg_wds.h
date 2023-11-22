#include <linux/version.h>
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,14)
#include <linux/sysinfo.h>
#else
#include <sys/sysinfo.h>
#endif
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

#include "rg_wds_protocl.h"
#include "rg_wds_beacon.h"
#include "rg_wds_json.h"
#include "rg_wds_gpio.h"
#include "rg_wds_recv_massage.h"
#include "rg_wds_pair_all.h"

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

#define DEV_FILE_MODEL                  "/proc/rg_sys/model"
#define DEV_FILE_SYSMAC                 "/proc/rg_sys/sys_mac"
#define DEV_FILE_SN                     "/proc/rg_sys/serial_num"
#define DEV_FILE_HARDWARE_VERSION       "/proc/rg_sys/hardware_version"
#define DEV_FILE_SOFTWARE_VERSION       "/etc/openwrt_version"

#define WDS_GETSN_CMD                   "cat /proc/rg_sys/serial_num"

#define DEV_301        "EST301"
#define DEV_302        "EST302"
#define DEV_300        "EST300"
#define DEV_310        "EST310"

/* device belong to 2.4G or 5G */
#define EST_2G         0
#define EST_5G         1

#define ATH_2G_WDS_NAME    "ath0"   //WDS接口
#define ATH_2G_MAG_NAME    "ath01"  //管理接口
#define ATH_5G_WDS_NAME    "ath1"
#define ATH_5G_MAG_NAME    "ath11"

#define WIFI_5G_WDS_NAME    "wifi1"
#define WIFI_2G_WDS_NAME    "wifi0"

#define ATH_MODE_STA        "sta"
#define ATH_MODE_AP         "ap"


#define LOOK_UNLOOK_EVENT       0x1
#define UNLOOK_LOOK_EVENT       0x2
#define AP_STA_EVENT             0x4
#define STA_AP_EVENT             0x8
#define LOOK_UNLOOK_EVENT_BIT   0
#define UNLOOK_LOOK_EVENT_BIT   1
#define AP_STA_EVENT_BIT         2
#define STA_AP_EVENT_BIT         3

//没有从wlanconfig list 获取到对应的mac的设备超过这个时间
#define WLANCONFIG_LIST_OFF_TIME 30

//CPE 链路不通情况下5分钟重启wifi，1小时重启设备
//ROOT 链路不通，且没有其他cpe情况下，20分钟重启wifi，4小时重启设备
#define WDS_KEEP_WIFI_RELOAD 5*60
#define WDS_KEEP_WIFI_REBOOT 12

/* 定义网络报文头部宏 */
#define WDS_ETH_HEAD_LEN        14
#define WDS_IP_HEAD_LEN         20
#define WDS_UDP_HEAD_LEN        8
#define WDS_PSEUDO_HEAD_LEN     12

#define WDS_KEEP_WIFI_ROOT_RELOAD 20*60
#define WDS_KEEP_WIFI_ROOT_REBOOT 6
extern char debug;
#define DEBUG(fmt,args...)                                                           \
{                                                                                          \
    if (debug == 1) {                                                                        \
        printf("[%s]:[%d] "#fmt"\n",__func__,__LINE__,##args);           \
    }                                                                                      \
}

#define DEBUG_ERROR(fmt,args...)                                                           \
{                                                                                          \
	printf("[%s]:[%d] "#fmt"\n",__func__,__LINE__,##args);           \
}

//软件版本相关
#define SOFT_VERSION_FILE  "/tmp/wds_softversion.json"
//软件版本相关


/* 表示一台设备的信息，与桥接无关 */
struct dev_info {
	char dev_type[20];
	unsigned char sys_mac[6];
	char sn[30];
	unsigned int ip;
	char host_name[65];
	char hardware_version[10];
    char software_version[40];
};

//ath 接口 相关信息，mac地址名称等等,包含其他的该ath口的一些配置信息，都认为和ath相关
struct dev_multi_info {
    unsigned long time_update;
    unsigned char sn[30];
    unsigned char peer_sn[30];
    unsigned char sys_mac[20];
    unsigned char ath_mac[20];
    unsigned char peermac[20];
    char dev_type[10];
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
    char lan2speed[15];
    char lan2link[15];
    char lan2duplex[15];

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
    char software_version[40];
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
    char flag;
    struct dev_multi_info *next;
};

//ath 接口 相关信息，mac地址名称等等,包含其他的该ath口的一些配置信息，都认为和ath相关
struct ath_info {
	unsigned char ath_wsd_name[20];
    unsigned char wifi_wsd_name[10];
	unsigned char ath_managed_name[20];
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
    unsigned char phymode[50];
};

//对端关联信息
struct pair_keep_time {
	unsigned long pair_live_get_num;    //接受保活报文的个数
	unsigned long pair_live_send_num;   //发送保活报文的个数
	unsigned long pair_live_get_time;   //收到保活报文的时间
};

struct gpio_info {
	char gpio_mode_num;
	char gpio_mode_value;
	char gpio_mode_value_last;
	char gpio_lock_num;
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

extern struct dev_info rg_dev_info_t;
extern struct ath_info rg_ath_info_t;
//不一定有对端信息，因此用指针表示
extern struct pair_dev_ath_info *rg_pair_info_heap_t;
extern struct gpio_info rg_gpio_info_t;
extern pthread_mutex_t rg_pair_mtx;
extern pthread_mutex_t mtx_wds_beacon_list;
extern pthread_mutex_t mtx_wds_softversion_file;

bool rg_wds_est_is_phy_key(char *dev_type);
int rg_wds_est_radio_type(char *dev_type);
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
char rg_wds_gpio_process(struct gpio_info *rg_gpio_info_t,struct ath_info *rg_ath_info_t);
void rg_wds_sysled_control(void);
void rg_wds_led_timer();
void rg_wds_send_sync_led_date(struct pair_dev_ath_info * p,char atcion);
int rg_send_raw_date(char *ifname,int data_len,unsigned char *send_msg,char *dst_char_mac);
void rg_wds_get_sync_led_date (char *date);
int rg_wds_revece_pactek_init();
void rg_wds_pair_list_stations(const char *ifname);
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
void rg_wds_get_lock_cpe(char *data,int len);
char rg_wds_lock();
char rg_wds_ath_set_ssid(char *ssid);
char rg_wds_ath_update(struct ath_info *ath_info_t);
char rg_wds_unlock();
char rg_wds_lock_2_unlock(struct ath_info *ath_info_t);
void wds_list_time_update();
void rg_wds_beacon_join_net_cpe();
void rg_wds_beacon_join_net_ap();
void rg_wds_lock_status_update(char *data);
void rg_wds_ap_add_maclist();
void rg_wds_ap_clear_maclist();
void rg_wds_cpe_set_bssid();
void rg_wds_cpe_clear_bssid();
unsigned char switch_mac_char_2_hex(char *src_char_mac,unsigned char *dst_mac);
char rg_wds_ath_bssid_check();
char rg_wds_lock_status_check();
char rg_wds_list_scanner();
void rg_wds_lock_gpio_process();
void rg_wds_sysinfo_update_cpe();
char  rg_wds_misc_exe_shell_cmd(char *cmd,char *buf,char len);
unsigned char rg_wds_misc_check_macaddress(unsigned char *mac);
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
void rg_wds_message_dev_process(char *str);
void rg_wds_get_cmd(char *cmd);
void rg_wds_write_info_all_list();
char rg_wds_misc_cmd(char *cmd,char *buf,char len);
char rg_wds_wifi_get_txpower(struct ath_info *ath_info_t);
u_int32_t rg_wds_misc_get_iface_netmask(char *ifname,char *buf);
void rg_wds_sw_status_status(char *name,char port,char *link,char *speed,char *duplex);
void rg_wds_uci_get_param(char *uci_param, char *buff, int len);
bool rg_wds_dfs_test_flag(void);
bool rg_wds_func_test_flag(void);

