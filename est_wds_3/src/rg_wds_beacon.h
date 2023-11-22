#define WDS_NTV_SN 					14
#define MAC_ADDR_LEN 				6
#define DEV_TYPE_LEN                16
#define DEV_NAME_LEN                65 
#define PRJ_NAME_LEN                65
#define IW_CMD_LEN                 38+17+DEV_NAME_LEN+1+PRJ_NAME_LEN+1+1+5+1
#define CONFIG_NETWORKID		"/etc/rg_config/networkid.json"
#define UPDATE_BCN_IW           "iwpriv %s set bcn_est_expend_info="
#define MAX_LEN_OF_SSID             32
#define LEN_PSK                     64
#define WIFI_DWONUP_FILE		"/tmp/wifi_downup.file"
enum{
    DOC_EXMPL_C_UNSPEC,
    DOC_EXMPL_C_ECHO,
    DOC_KEYERROR,
	DOC_SSID_KEY,
	DOC_CALIBRATE_RSSI,
    __DOC_EXMPL_C_MAX,
};

enum func_mode_ssid_key{
	SCAN_PAIR = 1,
	ONE_CC,
};

struct expand_wds_beacon_info_s{
	unsigned char dev_type[DEV_TYPE_LEN];
	unsigned char dev_mac[MAC_ADDR_LEN];
	unsigned char ath_mac[MAC_ADDR_LEN];
	unsigned char dev_name[DEV_NAME_LEN];
	unsigned char prj_name[PRJ_NAME_LEN];
	char dev_nm_stat;
	char prj_nm_stat;
	char pw_stat;
	
};

struct wds_beacon_info_s {
    char role;
    char wds_connect_status;
    int rssi;
    char wds_ssid[33];
	unsigned char mac[6];
    unsigned char sn[WDS_NTV_SN];
	//The following are the new parameters
	unsigned char is_exist_expend;
	struct expand_wds_beacon_info_s expand_info;
};

struct wds_scan_dev_netid_t {
	char role;
	unsigned char dev_sn[WDS_NTV_SN];
	char connect_stat;
	int rssi;
    unsigned char dev_type[DEV_TYPE_LEN];
	unsigned char dev_mac[MAC_ADDR_LEN];
	unsigned char ath_mac[MAC_ADDR_LEN];
	unsigned char dev_name[DEV_NAME_LEN];
	unsigned char prj_name[PRJ_NAME_LEN];
	char dev_nm_stat;
	char prj_nm_stat;
	char pw_stat;
	unsigned long time_update;
	struct wds_scan_dev_netid_t *next;
};

struct wds_ssid_netid_t {
    char role_cpe;
	char role_ap;
    char wds_connect_status_cpe;
    int rssi_ap;
	int rssi_cpe;
    char wds_ssid[33];
	unsigned long time_update_ap;
	unsigned long time_update_cpe;
	char rssi_max_count;
	char mac[6];
    unsigned char cpe_sn[14];
    unsigned char ap_sn[14];
	struct wds_ssid_netid_t *next;
};

typedef struct fast_wds_info_s {
	unsigned char app_ssid[MAX_LEN_OF_SSID+1];
	unsigned char app_key[LEN_PSK + 1];
	unsigned char channel;
	unsigned char func_mode;
	unsigned char countrycode[4];
}fast_wds_info_t;


//宏定义：根据generic netlink msg的具体构造定位
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))
#define MESSAGE_TO_KERNEL "Hello World from user space!"
#define ROLE_AP  6
#define ROLE_CPE 1

#define RSSI_DELETE 4
#define WDS_LIST_MAX_LENGTH 10
#define SCAN_DEV_LIST_MAX_LENGTH 16
#define WDS_LIST_UPTIME 60*2
#define SCANDEV_LIST_UPTIME 60
#define WDS_LIST_SSID_CHECK_UPTIME 120
#define WDS_LIST_RSSI_COMPARE 10

extern struct wds_ssid_netid_t *wds_ssid_list_p;

int rg_wds_beacon_pthread(void);
