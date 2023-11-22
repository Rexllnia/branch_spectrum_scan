struct wds_beacon_info_s {
    char role;
    char wds_connect_status;
    int rssi;
    char wds_ssid[33];
	unsigned char mac[6];
    unsigned char sn[14];
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

//宏定义：根据generic netlink msg的具体构造定位
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))
#define MESSAGE_TO_KERNEL "Hello World from user space!"
#define ROLE_AP  6
#define ROLE_CPE 1

#define RSSI_DELETE 4
#define WDS_LIST_MAX_LENGTH 10
#define WDS_LIST_UPTIME 60*2
#define WDS_LIST_SSID_CHECK_UPTIME 120
#define WDS_LIST_RSSI_COMPARE 10

extern struct wds_ssid_netid_t *wds_ssid_list_p;

int rg_wds_beacon_pthread(void);
