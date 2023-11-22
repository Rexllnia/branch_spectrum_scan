#define SYNC_BEGIN       0
#define SYNC_END         1
#define SYNC_CLEAR       2
#define SYNC_KEEP_LIVE   3

#define SYNC_LOCK        5
#define SYNC_VERSION     10

#define SYNC_SOFTWARE_VERSION  11
#define SYNC_SOFTWARE_UPDATE   12
#define SYNC_CMD         13
#define SYNC_INFO         14

struct wds_sn_mac_hostname {
	unsigned char sn[30];
	unsigned char system_mac[6];
	unsigned char hostname[65];
	unsigned char ath_mac[6];
	unsigned char role[4];
	unsigned char wds_status[4];
	unsigned char lock_status[8];
    unsigned int  ip_address;
    int  rssi;
	int  rate;
	unsigned long time_update;
	struct wds_sn_mac_hostname *next;
};

struct wds_keeplive_sysinfo_packet {
	unsigned char role;	 //0,表示cpe，1表示ap
	unsigned char name[10];
	unsigned char bssid[17];
	unsigned char lock;
	unsigned char sync_flag;
	unsigned char cpe_num;
	unsigned char unuse;
	unsigned char unuse2;
	unsigned char wds_len;
	unsigned char wds_sn_man_info[sizeof(struct wds_sn_mac_hostname)*5]; //数据结构递增，可以兼容不同的版本，CPE和AP的版本可能会不一样,最多8个
};

struct wds_keeplive_packet {
	unsigned char role;	 //0,表示cpe，1表示ap
	unsigned char name[10];
	unsigned char bssid[17];
	unsigned char lock;
	unsigned char sync_flag;
	unsigned char cpe_num;
	unsigned char unuse;
	unsigned char unuse2;
};

struct wds_info_packet_head {
	unsigned char role;	 //0,表示cpe，1表示ap
	unsigned char name[10];
	unsigned char bssid[17];
	unsigned char lock;
	unsigned char sync_flag;
	unsigned char cpe_num;
	unsigned char unuse;
	unsigned char unuse2;
	unsigned char wds_len;
};

struct wds_softversion_packet {
    unsigned char mac[6];
    unsigned char softverson[40];
};

struct wds_update_version_packet {
    unsigned int src_ip;
    unsigned char softverson[40];
};

struct wds_sync_led_packet {
	unsigned char role;	 //0,表示cpe，1表示ap
	unsigned char name[10];
	unsigned char bssid[17];
	unsigned char lock;
	unsigned char sync_flag;
	unsigned char cpe_num;
	unsigned char unuse;
	unsigned char unuse2;
};

struct wds_date_head {
	unsigned char role;	 //0,表示cpe，1表示ap
	unsigned char name[10];
	unsigned char bssid[17];
	unsigned char lock;
	unsigned char sync_flag;
	unsigned char cpe_num;
	unsigned char unuse;
	unsigned char unuse2;
};

struct mac_ip_udp_wds_packet {
	struct ether_header eth_header_date;
	struct iphdr ip;
	struct udphdr udp;
};

void rg_wds_fill_head(struct wds_date_head *data,char flag,char len);
