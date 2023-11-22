#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <uci.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <netinet/udp.h>
#include <json.h>

#define MODE_AP         1
#define MODE_CPE        0
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

#define SYNC_BEGIN 0
#define SYNC_END   1
#define SYNC_CLEAR   2

#define SYNC_KEEP_LIVE   3

#define REBOOT_TIME 60*5
#define SEND_TIME 20

#define SN_MAC_INIT 0     // 第一次初始化
#define SN_MAC_UPDATE 1   // 更新hostname信息
#define SN_MAC_ADD 2      //  添加新的设备
#define SN_MAC_DELET 3      // 设备的锁和模式发生变化

#define WDS_DOWN_TIME 3*60

#define WIFI_RELOAD_REASON_UNLOCK     1
#define WIFI_RELOAD_REASON_MODE       2
#define WIFI_RELOAD_REASON_NOCHECK    3
#define WIFI_RELOAD_REASON_CHECK      4





//CPE 链路不通情况下5分钟重启wifi，1小时重启设备
//ROOT 链路不通，且没有其他cpe情况下，30分钟重启wifi，5小时重启设备
#define WDS_KEEP_WIFI_RELOAD 5*60
#define WDS_KEEP_WIFI_REBOOT 12

#define WDS_KEEP_WIFI_ROOT_RELOAD 20*60
#define WDS_KEEP_WIFI_ROOT_REBOOT 6
#define CPE_LEN 8

unsigned int debug = 1;
char gpio[] = {MODE_GPIO,LOCK_GPIO};
char value[2];
pthread_mutex_t mtx;

int role;	 //0,表示cpe，1表示ap

struct wds_info {
	unsigned char ath_name[33];
	unsigned char ath_mac[20];
	unsigned char ath_mac_hex[6];
	unsigned char root_mac_hex[7];
	unsigned char ath_managed_name[20];
};

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

struct wds_packet {
	unsigned char role;	 //0,表示cpe，1表示ap
	unsigned char name[10];
	unsigned char bssid[17];
	unsigned char lock;
	unsigned char sync_flag;
	unsigned char cpe_num;
	unsigned char unuse;
	unsigned char unuse2;
	unsigned char wds_len;
	unsigned char wds_sn_man_info[sizeof(struct wds_sn_mac_hostname)*CPE_LEN]; //数据结构递增，可以兼容不同的版本，CPE和AP的版本可能会不一样,最多8个
};

struct cpe_list {
	unsigned char receve_status;
	unsigned long receve_timeout;
	unsigned char cpe_mac[6];
	struct cpe_list *next;
};

struct mac_ip_udp_wds_packet {
	struct ether_header eth_header_date;
	struct iphdr ip;
	struct udphdr udp;
	struct wds_packet date;
};

struct wds_keep_live {
	unsigned char status;
	unsigned int timeout;
};

struct wds_packet wds_packet_t;
struct cpe_list *cpe_dev_p = NULL;
struct wds_info ath_info_p;

unsigned char receve_status;
unsigned char *ifname = ath_info_p.ath_name;
unsigned char broadcast_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char dst_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
struct wds_sn_mac_hostname wds_sn_mac_hostname_head;
char wds_sn_write_flag = 0;
unsigned char lock_status_1;
unsigned char mac_list_1[256];


char wds_link_status;
int undefault_ssid_lock_status(int ap_mode, char *wds_ssid, char *maclist, char *bssid);
char wds_sn_mac_create_file_all(char flag);
int reload_wifi(char reason);

#define DEBUG(fmt,args...)                                                           \
{                                                                                          \
    if (debug == 1) {                                                                        \
        printf("[%s]:[%d] "#fmt"\n",__func__,__LINE__,##args);           \
    }                                                                                      \
}

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
int get_bssid_list(char *bssid_list) ;

u_int32_t get_iface_ip(const char *ifname)
{
	struct ifreq if_data;
	struct in_addr in;
	char *ip_str;
	char buf[50];
	int sockd;
	u_int32_t ip;

	/* Create a socket */
	if ((sockd = socket (AF_INET, SOCK_PACKET, htons(0x8086))) < 0) {
		return 0;
	}

	/* Get IP of internal interface */
	strcpy (if_data.ifr_name, ifname);

	/* Get the IP address */
	if (ioctl (sockd, SIOCGIFADDR, &if_data) < 0) {
		return 0;
	}
	memcpy ((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
	in.s_addr = ip;

	ip_str = inet_ntoa(in);

	memset(buf,0,sizeof(buf));
	memcpy(buf,ip_str,strlen(ip_str));

	//printf("ip %4x %s buf %s\n",ip,ip_str,buf);
	close(sockd);
	return ip;
}

static unsigned char switch_char_2_hex(unsigned char chStr)
{
    if (chStr >= '0' && chStr <= '9')
    {
    	//DEBUG("chStr %c",chStr);
        return (chStr - '0');
    }
    else if (chStr >= 'A' && chStr <= 'f')
    {
    	//DEBUG("chStr %c",chStr);
        return (chStr - 'A' + 10);
    }
    else if (chStr >= 'a' && chStr <= 'f')
    {
    	//DEBUG("chStr %c",chStr);
        return (chStr - 'a' + 10);
    }
    else
    {
    	//DEBUG("chStr %c",chStr);
        return 0;
    }
}

static unsigned char switch_mac_char_2_hex(char *src_char_mac,unsigned char *dst_mac)
{
    unsigned char achSrc[18];
    int  nIdx = 0;
    int  nTotal = 0;

 	memset(achSrc,0,18);
	memcpy(achSrc,src_char_mac,17);

	unsigned char *pchStr = strtok(achSrc, ":");
    while (NULL != pchStr) {
        dst_mac[nTotal] = ((switch_char_2_hex(*pchStr) << 4) & 0xf0) | (switch_char_2_hex(*(pchStr+1)) & 0x0f);
        pchStr = strtok(NULL, ":");
		nTotal++;
    }
    return 0;

}

int load_uci_config(char *type,char *name,char *option_name,char *buf,int len)
{
	unsigned char tmp[100];
	FILE *p;
	int i;

	memset(tmp,0,sizeof(tmp));
	sprintf(tmp,"uci -q get wireless.@wifi-iface[0].%s",option_name);
	if((p = popen(tmp, "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return;
	}
	
	fread(buf,sizeof(char),len,p);
	for (i = 0;i < len;i++) {
		if (buf[i] == '\n') {
			buf[i] = 0;
		}
	}

	pclose(p);
}

int set_uci_config(char *type,char *name,char *option_name,char *option_value,char attribute)
{
	unsigned char buf[100];

	memset(buf,0,sizeof(buf));

	//DEBUG("%s",buf);
	if (strlen(option_value) == 0) {
		sprintf(buf,"uci -q delete wireless.@wifi-iface[0].%s",option_name);
		DEBUG("%s",buf);
		system(buf);
	} else {
		if (attribute == UCI_ATTRI_OPTION) {
			sprintf(buf,"uci set wireless.@wifi-iface[0].%s=%s",option_name,option_value);
			DEBUG("%s",buf);
			system(buf);
		} else if (attribute == UCI_ATTRI_LIST) {
			sprintf(buf,"uci add_list wireless.@wifi-iface[0].%s=%s",option_name,option_value);
			DEBUG("%s",buf);
			system(buf);
		}
	}
	system("uci commit wireless");
}

void wds_set_lock_mode() {
	memset(wds_sn_mac_hostname_head.role,0,sizeof(wds_sn_mac_hostname_head.role));
	if (value[0] == 0) {
		memcpy(wds_sn_mac_hostname_head.role,"CPE",strlen("CPE"));
	} else {
		memcpy(wds_sn_mac_hostname_head.role,"AP",strlen("AP"));
	}
	memset(wds_sn_mac_hostname_head.lock_status,0,sizeof(wds_sn_mac_hostname_head.lock_status));
	if (value[1] == 0) {
		memcpy(wds_sn_mac_hostname_head.lock_status,"UNLOCK",strlen("UNLOCK"));
	} else {
		memcpy(wds_sn_mac_hostname_head.lock_status,"LOCK",strlen("LOCK"));
	}
}

int get_rssi()
{
    char buf[60];
    FILE *fd;

	if (strlen(ath_info_p.ath_name) == 0) {
		return 0;
	}
	
    memset(buf,0,sizeof(buf));
	sprintf(buf,"wlanconfig %s list | awk '{print $6}' | grep -v RSSI",ath_info_p.ath_name);

	if ((fd = popen(buf, "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return 0;
	}

	memset(buf,0,sizeof(buf));
	fread(buf,sizeof(char),sizeof(buf),fd);
	pclose(fd);
//	DEBUG("get_rssi %s",buf);
    return atoi(buf);	
}

int get_rate()
{
    char buf[60];
    FILE *fd;

	if (strlen(ath_info_p.ath_name) == 0) {
		return 0;
	}

    memset(buf,0,sizeof(buf));
	sprintf(buf,"wlanconfig %s list | awk '{print $5}' | grep -v RXRATE",ath_info_p.ath_name);

	if ((fd = popen(buf, "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return 0;
	}

	memset(buf,0,sizeof(buf));
	fread(buf,sizeof(char),sizeof(buf),fd);
	pclose(fd);
//	DEBUG("get_rssi %s",buf);
    return atoi(buf);	
}

void get_host_name(char *host_name_buf) {
	FILE *p;
	int i;
	if((p = popen("uci get system.@system[0].hostname", "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return;
	}
	memset(wds_sn_mac_hostname_head.hostname,0,sizeof(wds_sn_mac_hostname_head.hostname));
	fread(host_name_buf,sizeof(char),sizeof(wds_sn_mac_hostname_head.hostname) - 1,p);

	for (i = 0;i < sizeof(wds_sn_mac_hostname_head.hostname);i++) {
		if (host_name_buf[i] == '\n') {
			host_name_buf[i] = 0;
		}
	}

	pclose(p);

	memset(wds_sn_mac_hostname_head.role,0,sizeof(wds_sn_mac_hostname_head.role));
	if (value[0] == 0) {
		memcpy(wds_sn_mac_hostname_head.role,"CPE",strlen("CPE"));
	} else {
		memcpy(wds_sn_mac_hostname_head.role,"AP",strlen("AP"));
	}

	if (value[1] == 0) {
		memcpy(wds_sn_mac_hostname_head.lock_status,"UNLOCK",strlen("UNLOCK"));
	} else {
		memcpy(wds_sn_mac_hostname_head.lock_status,"LOCK",strlen("LOCK"));
	}

    //获取IP地址
    wds_sn_mac_hostname_head.ip_address = get_iface_ip("br-wan");
	//获取RSSI
    if (value[0] == MODE_CPE) {
		wds_sn_mac_hostname_head.rssi = get_rssi();
		wds_sn_mac_hostname_head.rate = get_rate();
    }
}

//超过5分钟没有收到保活认为CPE下线下线
char wds_update_link_time_cpe() {
	struct sysinfo info;
	struct wds_sn_mac_hostname *p;
	struct wds_sn_mac_hostname *p1;
	char flag = 0;

	sysinfo(&info);

	pthread_mutex_lock(&mtx);
	p = &wds_sn_mac_hostname_head;
	while (p->next != NULL) {
		p1 = p;
		p = p->next;
	
		if (info.uptime - p->time_update > WDS_DOWN_TIME) {
			//当设备处于锁定状态，或者是MACLIST不为空的情况下则认为当前有白名单，这个时候就状态为OFF
			//否则删除该设备
//			DEBUG("mac_list_1 %s",mac_list_1);
			if (memcmp(p->wds_status,WDS_OFF,strlen(WDS_OFF)) != 0 && strlen(mac_list_1) != 0 && value[0] == MODE_AP) {
				DEBUG("p->athmac %s is off",p->ath_mac);
				memset(p->wds_status,0,sizeof(p->wds_status));
				memcpy(p->wds_status,WDS_OFF,strlen(WDS_OFF));
				DEBUG(p->wds_status,sizeof(p->wds_status));
				flag = 1;
				//break;
			} else if (memcmp(p->wds_status,WDS_OFF,strlen(WDS_OFF)) != 0 && strlen(mac_list_1) == 0 && value[0] == MODE_AP) {
				//删除该节点
				flag = 1;
				//如果已经是尾节点，那么直接设置为NULL即可
				if (p->next == NULL) {
					p1->next = NULL;
				} else {
					p1->next = p->next;
				}

				DEBUG("p->athmac %s is off del",p->ath_mac);
				free(p);
			}
		}
	}
	pthread_mutex_unlock(&mtx);
	//保存到文件
	if (flag) {
		DEBUG("cpe is off");
		wds_sn_mac_create_file_all(0);
	}

}

//超过5分钟没有收到保活认为CPE下线下线
char wds_update_link_time_ap() {
	struct sysinfo info;
	struct wds_sn_mac_hostname *p;
	struct wds_sn_mac_hostname *p1;
	char flag = 0;

	sysinfo(&info);

	pthread_mutex_lock(&mtx);
	p = &wds_sn_mac_hostname_head;
	while (p->next != NULL) {
		p1 = p;
		p = p->next;
		//DEBUG("p->time_update %d info.uptime %d p->athmac %s",p->time_update,info.uptime,p->ath_mac);
		if ((info.uptime - p->time_update > WDS_DOWN_TIME) && memcmp(p->role,"AP",strlen("AP"))) {
			flag = 1;
		}
	}
	pthread_mutex_unlock(&mtx);
	//保存到文件
	if (flag) {
		wds_sn_mac_clear_date();
		wds_sn_mac_create_file_all(0);
	}
}

char wds_sn_mac_update_info_pair_from_cpe(struct wds_sn_mac_hostname *str) {
	struct wds_sn_mac_hostname *p;
	struct wds_sn_mac_hostname *p1;
	char flag_etc = 0;
	char flag_tmp = 0;
	char len = 0;
	struct sysinfo info;

	if (str == NULL) {
		DEBUG("NULL ");
		return FAIL;
	}

	//空的没办法比较，直接去掉
	if (strlen(str->sn) < 2) {
		DEBUG("strlen < 2");
		return FAIL;
	}
//	DEBUG("str->sn %s",str->sn);
	sysinfo(&info);
	pthread_mutex_lock(&mtx);
	p = &wds_sn_mac_hostname_head;
	p1 = p;
	p = p->next; //从第二个开始,第一个保留给本机
	
	while(p != NULL ) {
		if (memcmp(str->ath_mac,p->ath_mac,sizeof(str->ath_mac)) == 0) {
			if (memcmp(str->sn,p->sn,sizeof(str->sn)) != 0) {
				memset(p->sn,0,sizeof(p->sn));
				memcpy(p->sn,str->sn,sizeof(p->sn));
				flag_etc = 1;
				flag_tmp = 1;
			}

			if (memcmp(str->system_mac,p->system_mac,sizeof(str->system_mac)) != 0) {
				memset(p->system_mac,0,sizeof(p->system_mac));
				memcpy(p->system_mac,str->system_mac,sizeof(p->system_mac));
				flag_etc = 1;
				flag_tmp = 1;
			}

			if (memcmp(str->hostname,p->hostname,sizeof(str->hostname)) != 0) {
				memset(p->hostname,0,sizeof(p->hostname));
				memcpy(p->hostname,str->hostname,sizeof(p->hostname));
				flag_etc = 1;
				flag_tmp = 1;
			}

			if (memcmp(str->role,p->role,sizeof(str->role)) != 0) {
				memset(p->role,0,sizeof(p->role));
				memcpy(p->role,str->role,sizeof(p->role));
				flag_etc = 1;
				flag_tmp = 1;
			}
			//更新CPE状态，从AP端的角度来看
			if (memcmp(p->wds_status,WDS_ON,strlen(WDS_ON)) != 0) {
				memset(p->wds_status,0,sizeof(p->wds_status));
				memcpy(p->wds_status,WDS_ON,strlen(WDS_ON));
				flag_tmp = 1;
			}
			if (memcmp(str->lock_status,p->lock_status,sizeof(str->lock_status)) != 0) {
				memset(p->lock_status,0,sizeof(p->lock_status));
				memcpy(p->lock_status,str->lock_status,sizeof(p->lock_status));
//				DEBUG("p->lock_status %s",p->lock_status);
				flag_tmp = 1;
			}
			
			if (p->rate != str->rate) {
				p->rate = str->rate;
				flag_tmp = 1;
			}
			
			if (p->rssi != str->rssi) {
				p->rssi = str->rssi;
				flag_tmp = 1;
			}
			
			if (p->ip_address!= str->ip_address) {
				p->ip_address = str->ip_address;
				flag_tmp = 1;
			}

			p->time_update = info.uptime;
			break;
		}

		p1 = p;
		p = p->next;
		len++;
	}

    //锁住了就不允许有CPE接进来
    //没有找到匹配上，重新分配一个
	if (p == NULL && len < CPE_LEN) {
		struct wds_sn_mac_hostname *p_head;
		p_head = malloc(sizeof(struct wds_sn_mac_hostname));
		if (p_head != NULL) {
			memset(p_head,0,sizeof(struct wds_sn_mac_hostname));
			memcpy(p_head->ath_mac,str->ath_mac,sizeof(str->ath_mac));
			memcpy(p_head->sn,str->sn,sizeof(str->sn));
			memcpy(p_head->system_mac,str->system_mac,sizeof(str->system_mac));
			memcpy(p_head->hostname,str->hostname,sizeof(str->hostname));
			memcpy(p_head->role,str->role,sizeof(str->role));
			memcpy(p_head->wds_status,str->wds_status,sizeof(str->wds_status));
			memcpy(p_head->lock_status,str->lock_status,sizeof(str->wds_status));
			p_head->time_update = info.uptime;
			p1->next = p_head;
		}
	}

	pthread_mutex_unlock(&mtx);
	//写TMP文件，不会有文件系统损坏的风险
	if (flag_tmp == 1) {
		//wds_sn_mac_create_file_all(0);
		wds_sn_write_flag = 1;
	}
}

char wds_sn_mac_update_info_pair_from_ap(char len,char *str) {
	struct wds_sn_mac_hostname *p;
	struct wds_sn_mac_hostname *p1;
	struct wds_sn_mac_hostname *p_head;
	char i = 0;
	int rssi;
	struct sysinfo info;

	if (str == NULL) {
		return FAIL;
	}

	//每次收到AP的数据，就把数据结构全部释放
	wds_sn_mac_clear_date();
	sysinfo(&info);
	pthread_mutex_lock(&mtx);
	p1 = &wds_sn_mac_hostname_head;

	for (i = 0;i < len ;i++) {
		p = (struct wds_sn_mac_hostname *)(str + sizeof(struct wds_sn_mac_hostname) * i);
		//空的没办法比较，直接去掉
		if (strlen(p->sn) < 2) {
			continue;
		}

		//过滤本机
		if (memcmp(p->ath_mac,ath_info_p.ath_mac_hex,sizeof(ath_info_p.ath_mac_hex)) == 0) {
			continue;
		}
		//更新状态信息

		p_head = malloc(sizeof(struct wds_sn_mac_hostname));
		if (p_head != NULL) {
			memset(p_head,0,sizeof(struct wds_sn_mac_hostname));
			memcpy(p_head->ath_mac,p->ath_mac,sizeof(p->ath_mac));
			memcpy(p_head->sn,p->sn,sizeof(p->sn));
			memcpy(p_head->system_mac,p->system_mac,sizeof(p->system_mac));
			memcpy(p_head->hostname,p->hostname,sizeof(p->hostname));
			memcpy(p_head->role,p->role,sizeof(p->role));
			memcpy(p_head->wds_status,p->wds_status,sizeof(p->wds_status));
			memcpy(p_head->lock_status,p->lock_status,sizeof(p->lock_status));
			p_head->ip_address = p->ip_address;
			p_head->rssi = p->rssi;
			p_head->rate = p->rate;
			p_head->time_update = info.uptime;
			p1->next = p_head;
			p1 = p1->next;
		}
	}

	pthread_mutex_unlock(&mtx);
	//DEBUG("");
	//写TMP文件，不会有文件系统损坏的风险
	if (p_head != NULL) {
		wds_sn_mac_create_file_all(0);
	}
}

char wds_show_info() {
	struct wds_sn_mac_hostname *p;
	p = &wds_sn_mac_hostname_head;
	while (p != NULL) {
		DEBUG("p->sn %s",p->sn);
		DEBUG("p->hostname %s",p->hostname);
		DEBUG("p->role %s",p->role);
		DEBUG("p->wds_status %s",p->wds_status);
		DEBUG("p->lock_status %s",p->lock_status);
		DEBUG("p->ip %04x",p->ip_address);
		dump_date(p->ath_mac,6);
		dump_date(p->system_mac,6);
		p = p->next;
	}
}

char wds_copy_info(char *buf) {
	struct wds_sn_mac_hostname *p;

	unsigned char len = 0;
	p = &wds_sn_mac_hostname_head;
	while (p != NULL && len < 8) {
		memcpy(buf,p,sizeof(struct wds_sn_mac_hostname));
		buf = buf + sizeof(struct wds_sn_mac_hostname);
		len = len + 1;
		p = p->next;
	}

	return len;
}

void wds_sn_mac_clear_date() {
	pthread_mutex_lock(&mtx);
	struct wds_sn_mac_hostname * p;

	p = &wds_sn_mac_hostname_head;
	while (p->next != NULL) {
		struct wds_sn_mac_hostname * p1 = NULL;
		p1 = p->next;
		p->next = p->next->next;
		free(p1);
	}
	pthread_mutex_unlock(&mtx);
}

void wds_sn_mac_clear_file(flag) {
	int fd;
	char buf[1];

	memset(buf,0,sizeof(buf));

	/* 打开一个文件 */
	fd = open("/tmp/wds_info.json",O_RDWR);
	if(fd < 0)
	{
		printf("open file.txt failed\n");
	}
	else
	{
		/* 清空文件 */
		ftruncate(fd,0);
		/* 重新设置文件偏移量 */
		lseek(fd,0,SEEK_SET);
		close(fd);
	}


	if (flag) {
		/* 打开一个文件 */
		fd = open("/etc/config/wds_info.json",O_RDWR);
		if(fd < 0)
		{
			printf("open file.txt failed\n");
		}
		else
		{
			/* 清空文件 */
			ftruncate(fd,0);
			/* 重新设置文件偏移量 */
			lseek(fd,0,SEEK_SET);
			close(fd);
		}
	}
}

char wds_sn_mac_create_file(char *ssid_list,char len,char flag)
{
	int i = 0;
	char buf[20];
	struct wds_sn_mac_hostname * p;
	struct wds_sn_mac_hostname * p1;

	pthread_mutex_lock(&mtx);
	if (len == 0) {
		goto release_lock;
	}

	json_object *file = json_object_new_object();
	json_object *section = json_object_new_array();

	for (i;i < len;i++) {
		memset(buf,0,sizeof(buf));
		memcpy(buf,ssid_list + i*17,17);

		//比对链表，有的修订，没有的添加,多余的删除
		p = &wds_sn_mac_hostname_head;
		while (p->next != NULL) {
			p = p->next;
			if (memcmp(p->ath_mac,buf,strlen(buf)) == 0) {
				DEBUG("lock find ath info");
				break;
			}
		}
		json_object *item = json_object_new_object();
		if (p != NULL) {
			json_object_object_add(item, "SN", json_object_new_string(p->sn));
			json_object_object_add(item, "MAC", json_object_new_string(p->system_mac));
			json_object_object_add(item, "ATHMAC", json_object_new_string(buf));
			json_object_object_add(item, "HOSTNAME", json_object_new_string(p->hostname));
			json_object_object_add(item, "ROLE", json_object_new_string(p->role));
			json_object_object_add(item, "STATUS", json_object_new_string(p->wds_status));
			json_object_object_add(item, "LOCK", json_object_new_string(p->lock_status));
		} else {
			json_object_object_add(item, "SN", json_object_new_string(""));
			json_object_object_add(item, "MAC", json_object_new_string(""));
			json_object_object_add(item, "ATHMAC", json_object_new_string(buf));
			json_object_object_add(item, "HOSTNAME", json_object_new_string(""));
			json_object_object_add(item, "ROLE", json_object_new_string(""));
			json_object_object_add(item, "STATUS", json_object_new_string(""));
			json_object_object_add(item, "LOCK", json_object_new_string(""));
		}
		json_object_array_add(section, item);

	}

	json_object_object_add(file, "LIST", section);

	const char *str = json_object_to_json_string(file);
	int fd ;

	//清文件
	
	json_object_put(file);
	wds_show_info();
release_lock:
	pthread_mutex_unlock(&mtx);

}


//flag 用来表示十分写入etc，保存到flash空间的文件
char wds_sn_mac_create_file_all(char flag) {
	int len = 0;
	struct in_addr in;
	char buf[50];

	pthread_mutex_lock(&mtx);
	wds_sn_mac_clear_file(flag);

	struct wds_sn_mac_hostname *p;
	p = &wds_sn_mac_hostname_head;
	json_object *file = json_object_new_object();
	json_object *section = json_object_new_array();
//	DEBUG("");
	while (p->next != NULL && len < 8) {
		len++;
		p = p->next;
		//ap模式下，白名单maclist 不为空，则写入json需要根据maclist来过滤
		if (strlen(mac_list_1) != 0 && value[0] == MODE_AP) {
			json_object *item = json_object_new_object();
			json_object_object_add(item, "SN", json_object_new_string(p->sn));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
				p->system_mac[0],p->system_mac[1],p->system_mac[2],
				p->system_mac[3],p->system_mac[4],p->system_mac[5]);
			//dump_date(p->system_mac,6);
			json_object_object_add(item, "MAC", json_object_new_string(buf));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
				p->ath_mac[0],p->ath_mac[1],p->ath_mac[2],
				p->ath_mac[3],p->ath_mac[4],p->ath_mac[5]);	

			json_object_object_add(item, "ATHMAC", json_object_new_string(buf));
			json_object_object_add(item, "HOSTNAME", json_object_new_string(p->hostname));
			json_object_object_add(item, "ROLE", json_object_new_string(p->role));
			json_object_object_add(item, "STATUS", json_object_new_string(p->wds_status));
			json_object_object_add(item, "LOCK", json_object_new_string(p->lock_status));
			in.s_addr = p->ip_address; 
			DEBUG("p->ip_address %04x",p->ip_address);
			json_object_object_add(item, "IP_ADDRESS", json_object_new_string(inet_ntoa(in)));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->rate);
			json_object_object_add(item, "RATE", json_object_new_string(buf));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->rssi);
			json_object_object_add(item, "RSSI", json_object_new_string(buf));

			json_object_array_add(section, item);
		} else if (value[0] == MODE_CPE && memcmp(p->ath_mac,ath_info_p.ath_mac_hex,sizeof(ath_info_p.ath_mac_hex)) != 0) {
			//cpe模式下，过滤本机即可
			//判断如果是cpe模式下，本机信息不写入wds
			json_object *item = json_object_new_object();
			json_object_object_add(item, "SN", json_object_new_string(p->sn));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
				p->system_mac[0],p->system_mac[1],p->system_mac[2],
				p->system_mac[3],p->system_mac[4],p->system_mac[5]);
			//DEBUG("p->system_mac %s ",buf);
			//dump_date(p->system_mac,6);
			json_object_object_add(item, "MAC", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
			sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
				p->ath_mac[0],p->ath_mac[1],p->ath_mac[2],
				p->ath_mac[3],p->ath_mac[4],p->ath_mac[5]);	
			//DEBUG("p->ath_mac %s ",buf);
			//dump_date(p->ath_mac,6);
			json_object_object_add(item, "ATHMAC", json_object_new_string(buf));

			json_object_object_add(item, "HOSTNAME", json_object_new_string(p->hostname));
			json_object_object_add(item, "ROLE", json_object_new_string(p->role));
			json_object_object_add(item, "STATUS", json_object_new_string(p->wds_status));
			json_object_object_add(item, "LOCK", json_object_new_string(p->lock_status));
			in.s_addr = p->ip_address; 
			json_object_object_add(item, "IP_ADDRESS", json_object_new_string(inet_ntoa(in)));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->rate);
			//DEBUG("rate %s",buf);
			json_object_object_add(item, "RATE", json_object_new_string(buf));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->rssi);
			//DEBUG("rssi %s",buf);
			json_object_object_add(item, "RSSI", json_object_new_string(buf));

			json_object_array_add(section, item);
		} else  {      
			//其他情况下，全部加入到wds list
			json_object *item = json_object_new_object();
			json_object_object_add(item, "SN", json_object_new_string(p->sn));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
				p->system_mac[0],p->system_mac[1],p->system_mac[2],
				p->system_mac[3],p->system_mac[4],p->system_mac[5]);
			//DEBUG("p->system_mac %s ",buf);
			//dump_date(p->system_mac,6);
			json_object_object_add(item, "MAC", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
			sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
				p->ath_mac[0],p->ath_mac[1],p->ath_mac[2],
				p->ath_mac[3],p->ath_mac[4],p->ath_mac[5]);	
			//DEBUG("p->ath_mac %s ",buf);
			//dump_date(p->ath_mac,6);
			json_object_object_add(item, "ATHMAC", json_object_new_string(buf));

			json_object_object_add(item, "HOSTNAME", json_object_new_string(p->hostname));
			json_object_object_add(item, "ROLE", json_object_new_string(p->role));
			json_object_object_add(item, "STATUS", json_object_new_string(p->wds_status));
			json_object_object_add(item, "LOCK", json_object_new_string(p->lock_status));
			in.s_addr = p->ip_address; 
			json_object_object_add(item, "IP_ADDRESS", json_object_new_string(inet_ntoa(in)));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->rate);
			json_object_object_add(item, "RATE", json_object_new_string(buf));
			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->rssi);
			json_object_object_add(item, "RSSI", json_object_new_string(buf));
			
			json_object_array_add(section, item);
		}
	}

	json_object_object_add(file, "LIST", section);

	const char *str = json_object_to_json_string(file);
	//DEBUG("str %s",str);
	int fd;
	fd = open("/tmp/wds_info.json", O_CREAT | O_RDWR,0644);
	write(fd,str,strlen(str));
	close(fd);
//	DEBUG("flag %d",flag);
	if (flag) {
		DEBUG("save to etc !");
		fd = open("/etc/config/wds_info.json", O_CREAT | O_RDWR,0644);
		write(fd,str,strlen(str));
		close(fd);
	}
	json_object_put(file);

	pthread_mutex_unlock(&mtx);
}

char wds_sn_mac_read_info() {
	pthread_mutex_lock(&mtx);

	int fd;
	struct wds_sn_mac_hostname * p;
	struct wds_sn_mac_hostname * p1;
	struct sockaddr_in adr_inet; /* AF_INET */
	char buf[50];
	int i;

	struct json_object *obj_all_p;
	obj_all_p = json_object_from_file("/etc/config/wds_info.json");

	if (obj_all_p == NULL) {
		goto release_lock;
	}

	obj_all_p = json_object_object_get(obj_all_p, "LIST");
	if (obj_all_p != NULL) {
		p = &wds_sn_mac_hostname_head;
		for(i = 0; i < json_object_array_length(obj_all_p); i++) {
			json_object *section= json_object_array_get_idx(obj_all_p, i);
			json_object *item_sn = json_object_object_get(section, "SN");
			json_object *item_mac = json_object_object_get(section, "MAC");
			json_object *item_athmac = json_object_object_get(section, "ATHMAC");
			json_object *item_hostname = json_object_object_get(section, "HOSTNAME");
			json_object *item_role = json_object_object_get(section, "ROLE");
			json_object *item_status = json_object_object_get(section, "STATUS");
			json_object *item_lock= json_object_object_get(section, "LOCK");
			json_object *item_ip= json_object_object_get(section, "IP_ADDRESS");
			DEBUG("item_ip %s",json_object_to_json_string(item_ip));

			struct wds_sn_mac_hostname * p_head;
			p_head = malloc(sizeof(struct wds_sn_mac_hostname));
			if (p_head == NULL) {
				continue;
			}
			
			memset(p_head,0,sizeof(struct wds_sn_mac_hostname));
			//转化为16机制	
			memset(buf,0,sizeof(buf));
			memcpy(buf,json_object_to_json_string(item_athmac)+ 1,strlen(json_object_to_json_string(item_athmac)) - 2);
			switch_mac_char_2_hex(buf,p_head->ath_mac);		

			memcpy(p_head->sn,json_object_to_json_string(item_sn)+ 1,strlen(json_object_to_json_string(item_sn)) - 2);

			//转化为16机制	
			memset(buf,0,sizeof(buf));
			memcpy(buf,json_object_to_json_string(item_mac) + 1,strlen(json_object_to_json_string(item_mac)) - 2);
			switch_mac_char_2_hex(buf,p_head->system_mac);
			
			memcpy(p_head->hostname,json_object_to_json_string(item_hostname)+ 1,strlen(json_object_to_json_string(item_hostname)) - 2);
			memcpy(p_head->role,json_object_to_json_string(item_role)+ 1,strlen(json_object_to_json_string(item_role)) - 2);
			memcpy(p_head->wds_status,WDS_OFF,strlen(WDS_OFF));

			//IP地址
			memset(buf,0,sizeof(buf));	
			memcpy(buf,json_object_to_json_string(item_ip)+ 1,strlen(json_object_to_json_string(item_ip)) - 2);
			p_head->ip_address = inet_addr(buf);
			DEBUG("ip_address %s p->ip_address %04x",buf,p_head->ip_address);

			p->next = p_head;
			p = p_head;

			DEBUG("item_sn %s ",p_head->sn);
		}
	}
	json_object_put(obj_all_p);
	wds_show_info();
release_lock:
	pthread_mutex_unlock(&mtx);
	return SUCESS;
}

char wds_sn_mac_init() {
	int fd;
	char buf[50];
	pthread_mutex_lock(&mtx);
	memset(&wds_sn_mac_hostname_head,0,sizeof(struct wds_sn_mac_hostname));
	fd = open("/proc/rg_sys/serial_num", O_RDONLY);
	if (fd > 0) {
		 read(fd,wds_sn_mac_hostname_head.sn,sizeof(wds_sn_mac_hostname_head.sn));
		 close(fd);
	}

	fd = open("/proc/rg_sys/sys_mac", O_RDONLY);
	if (fd > 0) {
		 memset(buf,0,sizeof(buf));
		 read(fd,buf,sizeof(buf));
		 //转化为16机制
		 switch_mac_char_2_hex(buf,wds_sn_mac_hostname_head.system_mac);
		 close(fd);
	}
	get_host_name(wds_sn_mac_hostname_head.hostname);
	memset(buf,0,sizeof(buf));
	memcpy(buf,ath_info_p.ath_mac,sizeof(ath_info_p.ath_mac));
	switch_mac_char_2_hex(buf,wds_sn_mac_hostname_head.ath_mac);
	//dump_date(wds_sn_mac_hostname_head.system_mac,6);
	//dump_date(wds_sn_mac_hostname_head.ath_mac,6);
	memcpy(wds_sn_mac_hostname_head.wds_status,WDS_ON,strlen(WDS_ON));

	DEBUG("sn %s system_mac %s hostname %s role %s lock_status %s ath_mac %s",wds_sn_mac_hostname_head.sn, \
			wds_sn_mac_hostname_head.system_mac,\
			wds_sn_mac_hostname_head.hostname,\
			wds_sn_mac_hostname_head.role,\
			wds_sn_mac_hostname_head.lock_status,\
			wds_sn_mac_hostname_head.ath_mac\
			);
	wds_set_lock_mode();
	wds_show_info();
	pthread_mutex_unlock(&mtx);
}

int wds_revece_pactek()
{
	DEBUG("");
	char errBuf[PCAP_ERRBUF_SIZE], *devStr;
	while (1) {
		/* open a device, wait until a packet arrives */
		//pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
		//snaplen是整形的，它定义了将被pcap捕捉的最大字节数
		//当promisc设为true时将置指定接口为混杂模式
		//to_ms是读取时的超时值，单位是毫秒(假如为0则一直嗅探直到错误发生，为-1则不确定)
		pcap_t * device = pcap_open_live(ath_info_p.ath_name, 2000, 0, 0, errBuf);

		if(!device)
		{
			printf("error: pcap_open_live(): %s\n", errBuf);
			sleep(3);
			continue;
		}

		/* construct a filter */
		struct bpf_program filter;
		pcap_compile(device, &filter, "dst port 50001 or src port 50001", 1, 0);
		pcap_setfilter(device, &filter);

		/* wait loop forever */
		int id = 0;
		pcap_loop(device, -1, getPacket, (u_char*)&id);

		pcap_close(device);
		sleep(3);
		DEBUG("");
	}
	return FAIL;
}

unsigned short checksum(unsigned short *buf, int nword)
{
    unsigned long sum;
    for(sum = 0; nword > 0; nword--)
    {
        sum += htons(*buf);
        buf++;
    }
    sum = (sum>>16) + (sum&0xffff);
    sum += (sum>>16);
    return ~sum;
}

int send_raw_date(unsigned char *send_msg,char *dst_char_mac)
{
	unsigned char *tmp;
	int len;
	char wds_sync_fail_count = 0;
	struct sysinfo info;
	int ap_flag;
	unsigned char src_mac[6];
	unsigned char dst_hex_mac[6];
	struct  mac_ip_udp_wds_packet *wds_p = (struct mac_ip_udp_wds_packet *)send_msg;
	unsigned char ip_head[24] = {
									0x45,0xf0,0x00,0x00,
								    0x00,0x00,0x00,0x00,
									0x80,17,0x00,0x00,
									0,0,0,0,
									0,0,0,0,
									0xc3,0x51,0xc3,0x51
								 };

	memset(src_mac,0,sizeof(src_mac));
	if (FAIL == get_mac(ath_info_p.ath_name,src_mac)) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}
	
    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw_fd < 0) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}

	if (dst_char_mac != NULL) {
		tmp = send_msg;
		memcpy(tmp,dst_char_mac,6);
	}
   	tmp = send_msg + 6;
	memcpy(tmp,src_mac,sizeof(src_mac));
	tmp = send_msg + 14;
	memcpy(tmp,ip_head,sizeof(ip_head));
	//DEBUG("flag %d",wds_p->date.sync_flag);
	//sdfa
	if (wds_p->date.sync_flag == SYNC_KEEP_LIVE) {
		if((len = sizeof(struct wds_packet)) % 2 == 1)
		{
			len++;
		}
	} else {
		if((len = (sizeof(struct wds_packet)) - sizeof(struct wds_sn_mac_hostname)*CPE_LEN) % 2 == 1)
		{
			len++;
		}
	}

	//DEBUG("len %d",len);
    *((unsigned short *)&send_msg[16]) = htons(20+8+len);
    *((unsigned short *)&send_msg[14+20+4]) = htons(8+len);

    unsigned char pseudo_head[1500] = {
		0,  0,	0,  0,	  //src_ip: 10.221.20.11
		0,  0,	0,  0,	  //dst_ip: 10.221.20.10
        0x00, 17,  0x00, 0x00,    // 0,17,#--16位UDP长度--20个字节
    };

    *((unsigned short *)&pseudo_head[10]) = htons(8 + len); //为头部中的udp长度（和真实udp长度是同一个值）
    memcpy(pseudo_head+12, send_msg+34, 8+len); //--计算udp校验和时需要加上伪头部--
    //对IP首部进行校验
    *((unsigned short *)&send_msg[24]) = htons(checksum((unsigned short *)(send_msg+14),20/2));
	//6.--对UDP数据进行校验--
    *((unsigned short *)&send_msg[40]) = htons(checksum((unsigned short *)pseudo_head,(12+8+len)/2));

    struct sockaddr_ll sll;
    struct ifreq ethreq;

    strncpy(ethreq.ifr_name, ath_info_p.ath_name, IFNAMSIZ);

    if(-1 == ioctl(sock_raw_fd, SIOCGIFINDEX, &ethreq))
    {
        perror("ioctl");
        close(sock_raw_fd);
        return FAIL;
    }

    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex;
	len = sendto(sock_raw_fd, send_msg, 14+20+8+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
	close(sock_raw_fd);
}

int wds_send_keep_date(char *dst_mac) {
	struct  mac_ip_udp_wds_packet wds_keep_live_t;
	char ap_mac[20];
	char mac_dst[6];
	struct wds_sn_mac_hostname *wds_info_p;
	
	memset(&wds_keep_live_t,0,sizeof(struct  mac_ip_udp_wds_packet));

	//广播方式
	wds_keep_live_t.eth_header_date.ether_type = htons(ETHERTYPE_IP);
	memset(wds_keep_live_t.eth_header_date.ether_dhost, 0xff, 6);

	//当前设备模式
	wds_keep_live_t.date.role = value[0];
	wds_keep_live_t.date.lock = value[1];

	wds_keep_live_t.date.unuse = 0x55;
	wds_keep_live_t.date.unuse2 = 0xaa;

	memcpy(wds_keep_live_t.date.name,"abcd",strlen("abcd"));
	wds_keep_live_t.date.sync_flag = SYNC_KEEP_LIVE;
	//CPE端广播 ,CPE首先发起报文

	//发送mac sn 等信息,hostname会随时间改变，所以要实时更新
	get_host_name(wds_sn_mac_hostname_head.hostname);
	if (value[0] == MODE_CPE) {
		//DEBUG("sizeof wds_sn_man_info %d",sizeof(wds_keep_live_t.date.wds_sn_man_info));
		memcpy(wds_keep_live_t.date.wds_sn_man_info,&wds_sn_mac_hostname_head,sizeof(struct wds_sn_mac_hostname));
		memset(ap_mac,0,sizeof(ap_mac));
		get_bssid_list(ap_mac);
		memset(mac_dst,0,sizeof(mac_dst));
		switch_mac_char_2_hex(ap_mac,mac_dst);
		//dump_date(mac_dst,sizeof(mac_dst));
//		DEBUG("ap_mac %s",ap_mac);
		//改为单播
		if (strlen(ap_mac) == 17) {
			send_raw_date(&wds_keep_live_t,mac_dst);
			return SUCESS;
		}
	} else if (value[0] == MODE_AP) {
		//AP端返回报文
		wds_keep_live_t.date.wds_len = wds_copy_info(wds_keep_live_t.date.wds_sn_man_info);
		send_raw_date(&wds_keep_live_t,dst_mac);
		return SUCESS;
	} else {
		return FAIL;
	}
}

int process_link_check()
{
	struct sysinfo info;
	unsigned long time_reload = 0;
	unsigned char time_reload_num = 0;

	while (1) {
		sleep(5);
		if (value[0] == MODE_CPE ) {
			wds_update_link_time_ap();

			//发送link 检查报文
			//发送广播报文
			if (wds_send_keep_date(NULL) == FAIL) {
				//报文发送失败情况下，对方也不收到，也不用做检查了
				DEBUG("send error");
				continue;
			}
			sysinfo(&info);
			//首次赋值
			//DEBUG("time_reload %d info.uptime %d keeptime %d time_reload_num %d",time_reload,info.uptime,info.uptime - time_reload,time_reload_num);
			if (time_reload == 0) {
				time_reload = info.uptime;
			}

			if (info.uptime - time_reload > WDS_KEEP_WIFI_RELOAD) {
				time_reload = info.uptime;
				time_reload_num++;
				//重启wifi
				reload_wifi(WIFI_RELOAD_REASON_CHECK);
			}

			//重启设备
			// 连续12次，1个小时不能用就重启设备
			if (time_reload_num > WDS_KEEP_WIFI_REBOOT) {
				//如果重启失败，则认为当前OK，开始下一个循环
				if (reboot_ap() == FAIL ) {
					wds_link_status = 1;
				}
			}

			//wds_link_status 是否接到link 应答报文的标志
			if (wds_link_status == 1) {
				wds_link_status = 0;
				time_reload = info.uptime;
				time_reload_num = 0;
				//DEBUG("wds_link_status %d,time_reload %d time_reload_num %d",wds_link_status,time_reload,time_reload_num);
			}
		} else {
			sysinfo(&info);
			wds_update_link_time_cpe();
			if (wds_sn_write_flag) {
				wds_sn_mac_create_file_all(0);
				wds_sn_write_flag = 0;
			}
			//首次赋值
			//DEBUG("time_reload %d info.uptime %d keeptime %d time_reload_num %d",time_reload,info.uptime,info.uptime - time_reload,time_reload_num);
			if (time_reload == 0) {
				time_reload = info.uptime;
			}

			if (info.uptime - time_reload > WDS_KEEP_WIFI_ROOT_RELOAD) {
				time_reload = info.uptime;
				time_reload_num++;
				//重启wifi
				reload_wifi(WIFI_RELOAD_REASON_CHECK);
			}

			//重启设备
			// 连续12次，1个小时不能用就重启设备
			if (time_reload_num > WDS_KEEP_WIFI_ROOT_REBOOT) {
				//如果重启失败，则认为当前OK，开始下一个循环
				if (reboot_ap() == FAIL ) {
					wds_link_status = 1;
				}
			}

			//wds_link_status 是否接到link 应答报文的标志
			if (wds_link_status == 1) {
				wds_link_status = 0;
				time_reload = info.uptime;
				time_reload_num = 0;
			}
		}
	}
}


int ap_sync_unlock_led(char status) {
	char ssid_list[256];
	char wds_ssid[33];
	char des_mac[6];
	char ssid_count = 0;
	struct  mac_ip_udp_wds_packet led_unlock_ap_t;
	char i,j;

	memset(ssid_list,0,sizeof(ssid_list));
	memset(&led_unlock_ap_t,0,sizeof(struct  mac_ip_udp_wds_packet));

	led_unlock_ap_t.eth_header_date.ether_type = htons(ETHERTYPE_IP);
	memset(led_unlock_ap_t.eth_header_date.ether_dhost, 0xff, 6);

	ssid_count = get_bssid_list(ssid_list);
	//DEBUG("ssid_list %s ssid_count %d status %d",ssid_list,ssid_count,status);

	memset(wds_ssid, 0, sizeof(wds_ssid));
	load_uci_config("wifi-iface", "wds", "ssid", wds_ssid, sizeof(wds_ssid));

	/*
	 * 1、非锁定，桥接ssid不为缺省值时，sys灯与缺省ssid一样。
	 * 2、非锁定，桥接ssid为缺省值时，无桥接设备的情况下，sys灯常亮。
	 */
	if (value[0] == MODE_AP && status == 1 && ssid_count == 0) {
		//DEBUG("mode %d ssid_list %s ssid_count %d status %d wds_ssid %s", value[0], ssid_list, ssid_count, status, wds_ssid);
		cpe_ap_sync_unlock_led(0, SYNC_BEGIN);
	}

	memcpy(led_unlock_ap_t.date.name,"ruijie",strlen("ruijie"));

	for (j = 0;j < ssid_count; j++) {
		led_unlock_ap_t.date.role = MODE_AP;
		led_unlock_ap_t.date.lock = UNLOCK;
		led_unlock_ap_t.date.cpe_num = ssid_count;
		led_unlock_ap_t.date.unuse = 0x55;
		led_unlock_ap_t.date.unuse2 = 0xaa;

		//CPE全部开始闪烁5S
		led_unlock_ap_t.date.sync_flag = SYNC_BEGIN;
		if (status == 0) {
			led_unlock_ap_t.date.lock = LOCK;
			led_unlock_ap_t.date.sync_flag = SYNC_CLEAR;
		}

		for (i = 0;i < ssid_count;i++) {
			memcpy(led_unlock_ap_t.date.bssid,ssid_list + i*17,17);
			memset(des_mac,0,sizeof(des_mac));
			switch_mac_char_2_hex(led_unlock_ap_t.date.bssid,des_mac);
			send_raw_date(&led_unlock_ap_t,des_mac);
			//send_raw_date(&led_unlock_ap_t,NULL);
			//DEBUG("SYNC_BEGIN %s",led_unlock_ap_t.date.bssid);
		}
		
		//AP端同步开始亮
		if (led_unlock_ap_t.date.lock == LOCK) {
			cpe_ap_sync_unlock_led(ssid_count,SYNC_CLEAR);
			led_unlock_ap_t.date.sync_flag = SYNC_CLEAR;
			for (i = 0;i < ssid_count;i++) {
				memcpy(led_unlock_ap_t.date.bssid,ssid_list + i*17,17);
				memset(des_mac,0,sizeof(des_mac));
				switch_mac_char_2_hex(led_unlock_ap_t.date.bssid,des_mac);
				send_raw_date(&led_unlock_ap_t,des_mac);
				//send_raw_date(&led_unlock_ap_t,NULL);
				//DEBUG("SYNC_CLEAR %s",led_unlock_ap_t.date.bssid);
			}

			return;
		} else {
			cpe_ap_sync_unlock_led(ssid_count,SYNC_BEGIN);
		}
		usleep(500000);

		led_unlock_ap_t.date.sync_flag = SYNC_END;
		for (i = 0;i < ssid_count;i++) {
			memcpy(led_unlock_ap_t.date.bssid,ssid_list + i*17,17);
			memset(des_mac,0,sizeof(des_mac));
			switch_mac_char_2_hex(led_unlock_ap_t.date.bssid,des_mac);
			send_raw_date(&led_unlock_ap_t,des_mac);
			//send_raw_date(&led_unlock_ap_t,NULL);
			//DEBUG("SYNC_END %s",led_unlock_ap_t.date.bssid);
		}
		cpe_ap_sync_unlock_led(ssid_count,SYNC_END);
		usleep(500000);
	}
}

void cpe_ap_sync_unlock_led(char cpe_count,char action) {
	//DEBUG("cpe_count %d action %d",cpe_count,action);
	if (action == SYNC_CLEAR || cpe_count == 0) {
		system("led_send_message \"wds_sync;clear\" >/dev/null");
		return ;
	}

	if (action == SYNC_END) {
		system("led_send_message \"wds_sync;end\" >/dev/null");
		return ;
	}

	if (action == SYNC_BEGIN) {
		//先全部清掉
		system("led_send_message \"wds_sync;end\" >/dev/null");
		system("led_send_message \"wds_sync;begin\" >/dev/null");
		return;
	}

}
static char ap_sync_status = 0;
static char time_out = 1;

/*
 * 返回值为1时，真正锁定
 * 返回值为0时，未真正锁定
 */
int undefault_ssid_lock_status(int ap_mode, char *wds_ssid, char *maclist, char *bssid)
{
	int ret;

	/* 非缺省ssid，真正锁定 */
	if (strcmp(wds_ssid, (char *)&DEF_SSID)) {
		/* 文件不存在 */
		ret = access("/tmp/tmp_lock", 0);
		if (ret != 0) {
			return 1;	//soft_lock=1,已锁定
		} else {
			return 0;	//soft_lock=0,未锁定
		}
	}
	//缺省ssid, AP模式
	if (ap_mode == MODE_AP) {
		if (strlen(maclist) == 0) {
			return 0;	//soft_lock=0,未锁定
		}
		return 1;
	}
	//缺省ssid, CPE模式
	if (ap_mode == MODE_CPE) {
		if (strlen(bssid) == 0) {
			return 0;	//soft_lock=0,未锁定
		}
		return 1;
	}
}

int process_sync_unlock_led()
{
	int ap_mode;
	int lock_status;
	struct sysinfo info;
	char lock_bssid[100];
	char wds_ssid[33];
	char mac_list_tmp[256];
	int soft_lock;

	sleep(2);
	DEBUG("");
	while (1) {
		sleep(3);
		ap_mode = value[0];
		lock_status = value[1];
		memset(lock_bssid, 0, sizeof(lock_bssid));
		memset(mac_list_tmp, 0, sizeof(mac_list_tmp));
		load_uci_config("wifi-iface", "wds", "maclist", mac_list_tmp, sizeof(mac_list_tmp));
		//只有当不相等的时候，才拷贝
		if (memcmp(mac_list_tmp,mac_list_1,sizeof(mac_list_tmp)) != 0) {
			memcpy(mac_list_1,mac_list_tmp,sizeof(mac_list_tmp));
			DEBUG("mac_list_1 %s",mac_list_1);
		}
		memset(wds_ssid, 0, sizeof(wds_ssid));
		load_uci_config("wifi-iface", "wds", "bssid", lock_bssid, sizeof(lock_bssid));
		load_uci_config("wifi-iface", "wds", "ssid", wds_ssid, sizeof(wds_ssid));

		soft_lock = undefault_ssid_lock_status(ap_mode, wds_ssid, mac_list_1, lock_bssid);
		lock_status &= soft_lock;
		lock_status_1 = lock_status;
		if (lock_status == LOCK) {
			// 判断uci配置不为空、或桥接ssid不为缺省ssid，真正锁定
			//DEBUG("lock_bssid %d mac_list %d ap_sync_status %d", strlen(lock_bssid), strlen(mac_list), ap_sync_status);
			if (ap_sync_status) {
				ap_sync_status = 0;
				//最后一次发送
				ap_sync_unlock_led(ap_sync_status);
			}
			continue;
		}

		/*
		 *  未锁定或锁空时，对sys灯进行处理（非缺省ssid特殊处理，常亮）。AP端闪烁桥接个数
		 *  1、未锁定有三种情况：启机未锁定、lock-->unlock、缺省ssid时未真正锁定。
		 *  2、非缺省ssid时，根据物理锁的状态区分状态机状态，unlock的状态机为1，lock的状态机为0。
		 */
		 if (ap_mode == MODE_AP) {
			if (strlen(mac_list_1) == 0) {
				//DEBUG("wds_ssid %s mac_list is %d ap_sync_status %d", wds_ssid, strlen(mac_list), ap_sync_status);
				ap_sync_status = 1;
				ap_sync_unlock_led(ap_sync_status);
			}
		}
	}
}

void dump_date(unsigned char *buf,int len){
	int i;
	if (debug) {
		for(i=0; i<len; ++i)
		{
		  printf(" %02x", buf[i]);
		  if((i + 1) % 16 == 0)
		  {
			printf("\n");
		  }
		}
		printf("\n");
	}
}



//获取当前锁定状态
int get_lock_status() {
	char buf[100];
}


//获取当前设备角色
int get_role() {

	role = 0;
}


//重启设备，并标记曾经重启过
int reboot_cpe()
{
	DEBUG("");
}

//重启设备，并标记曾经重启过
int int_cpe()
{
	DEBUG("");
}

int managed_ath(){
	char buf[50];
	char buf_1[10];
	int  fd;
	int  sta_num = 0;

	if (strlen(ath_info_p.ath_managed_name) == 0) {
		get_athinfo();
	}

	if (strlen(ath_info_p.ath_managed_name) == 0) {
		return 0;
	}
	memset(buf,0,sizeof(buf));
	sprintf(buf,"wlanconfig %s list | wc -l",ath_info_p.ath_managed_name);
	if ((fd = popen(buf, "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return 0;
	}

	memset(buf_1,0,sizeof(buf_1));
	while (fgets(buf_1, sizeof(buf_1), fd)) {
		sta_num = atoi(buf_1);
		DEBUG("sta_num %d",sta_num);
	}
	close(fd);

	if (sta_num >=2 ) {
		sta_num = sta_num -1;
	}
	return sta_num;
}


//重启设备，并标记曾经重启过
int reboot_ap()
{
	char buf[30];
	if (managed_ath() >=1) {
		memset(buf,0,sizeof(buf));
		sprintf(buf,"ifconfig %s down",ath_info_p.ath_name);
		system(buf);
		DEBUG("can not reboot ,sta is still assoc!,just do down ");
		sleep(10);
		memset(buf,0,sizeof(buf));
		sprintf(buf,"ifconfig %s up",ath_info_p.ath_name);
		system(buf);
		DEBUG("can not reboot ,sta is still assoc!,just do up ");
		return FAIL;
	}
	system("reboot");
	return SUCESS;
}

//重启设备，并标记曾经重启过
int int_ap()
{
	DEBUG("reboot");
	system("reboot");
}


//写入消息，消息包含 bssid
int int_packet()
{
	memset(&wds_packet_t,0,sizeof(struct wds_packet));
	wds_packet_t.role = 1;
	memcpy(wds_packet_t.name,"abcd",strlen("abcd"));
	get_bssid();
}

int get_athinfo() {
	int fd;
	FILE *p_ath;
	FILE *p_wds;
	FILE *p_bssid;
	char buf[100];
	char buf_2[100];
	int i ;
	char *p;
	char wds_flag = 0;
	int ret = SUCESS;

	while (1) {
		sleep(5);
		memset(ath_info_p.ath_mac,0,sizeof(ath_info_p.ath_mac));
		memset(ath_info_p.ath_managed_name,0,sizeof(ath_info_p.ath_managed_name));
		if((p_ath = popen("ls /sys/class/net/ | grep ath", "r")) == NULL) {
			printf("%s %d fail/n",__func__,__LINE__);
			continue;
		}

		memset(buf,0,sizeof(buf));
		while (fgets(buf, sizeof(buf), p_ath)) {
			rm_enter_key(buf,strlen(buf));

	        memset(buf_2,0,sizeof(buf_2));
	        sprintf(buf_2,"iwpriv %s get_wds",buf);
			if ((p_wds = popen(buf_2, "r")) == NULL) {
				printf("%s %d fail/n",__func__,__LINE__);
				ret = FAIL;
				break;
			}

			memset(buf_2,0,sizeof(buf_2));
			while (fgets(buf_2, sizeof(buf_2), p_wds)) {
				p = strtok(buf_2,":");
				char count = 0;
				while (p != NULL) {
					if (count == 0) {
						count++;
						p = strtok(NULL,":");
						continue;
					}
					wds_flag = atoi(p);
					if (wds_flag) {
						memcpy(ath_info_p.ath_name,buf,sizeof(ath_info_p.ath_name)); 
					} else {
						memcpy(ath_info_p.ath_managed_name,buf,sizeof(ath_info_p.ath_managed_name)); 
					}
					p = strtok(NULL,":");
				}

			}
			pclose(p_wds);

		}
		pclose(p_ath);

	    memset(buf_2,0,sizeof(buf_2));
	    sprintf(buf_2,"/sys/class/net/%s/address",ath_info_p.ath_name);
	    fd = open(buf_2, O_RDONLY);
	    if (fd < 0) {
			continue;
	    }
	    if (read(fd, ath_info_p.ath_mac, MAC_LEN) < 0) {
	        close(fd);
			continue;
	    }
		close(fd);
		DEBUG("ath_info_p.ath_mac %s %d ",ath_info_p.ath_mac,strlen(ath_info_p.ath_mac));
		if (strlen(ath_info_p.ath_mac) == MAC_LEN) {
			switch_mac_char_2_hex(ath_info_p.ath_mac,ath_info_p.ath_mac_hex);
			
			return SUCESS;
		}
	}

	return FAIL;
}

//获取当前br-wan mac地址
int get_mac(char *ifname,unsigned char *mac)
{
    int  sockfd;
    struct sockaddr_in  sin;
    struct ifreq ifr;

	if (strlen(ifname) == 0) {
		return FAIL;
	}

	while(1) {
	    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	    if (sockfd == -1) {
	        perror("socket error");
			sleep(1);
	        continue;
	    }

	    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);      //Interface name

	    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {  //SIOCGIFHWADDR 获取hardware address
	    	memset(mac,0,6);
	        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	        //DEBUG("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		    close(sockfd);
		    return SUCESS;
	    }
		DEBUG("get mac fail");
		close(sockfd);
		sleep(1);
	}
}

void get_mac_assi() {
	char buf_2[50];
	int fd;

	memset(buf_2,0,sizeof(buf_2));
	memset(ath_info_p.ath_mac,0,17);
	sprintf(buf_2,"/sys/class/net/%s/address",ath_info_p.ath_name);
	fd = open(buf_2, O_RDONLY);
	memset(buf_2,0,sizeof(buf_2));
	if (fd < 0) {
		return;
	}
	read(fd, buf_2, sizeof(buf_2));
	//DEBUG("buf_2 %s",buf_2);
	memcpy(ath_info_p.ath_mac,buf_2,17);

	close(fd);
}

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
    struct mac_ip_udp_wds_packet *mac_all_date;
	struct wds_packet *wds_receve;
    struct sysinfo info;
	char ap_mode = value[0];
	char lock_status = lock_status_1;
	char ath_mac[6];
    int i;

	get_mac_assi();
	switch_mac_char_2_hex(ath_info_p.ath_mac,ath_mac);
	wds_receve = (struct wds_packet *)((u_char *)packet + 44);
	//dump_date(packet,6);
	if (ap_mode == MODE_CPE) {
		//开始同步信息
		if (wds_receve->lock == UNLOCK && wds_receve->sync_flag == SYNC_BEGIN  && lock_status == UNLOCK && wds_receve->role == MODE_AP) {
			if (!strncmp(wds_receve->bssid,ath_info_p.ath_mac,MAC_LEN)) {
				cpe_ap_sync_unlock_led(wds_receve->cpe_num,SYNC_BEGIN);
				//DEBUG("get root SYNC_BEGIN");
			}
			return;
		}
		//结束同步信息
		if (wds_receve->lock == UNLOCK && wds_receve->sync_flag == SYNC_END  && lock_status == UNLOCK && wds_receve->role == MODE_AP) {
			if (!strncmp(wds_receve->bssid,ath_info_p.ath_mac,MAC_LEN)) {
				cpe_ap_sync_unlock_led(wds_receve->cpe_num,SYNC_END);
				//DEBUG("get root SYNC_END");
			}
			return;
		}

		//保持常亮，等待 lock
		if (wds_receve->lock == LOCK && wds_receve->sync_flag == SYNC_CLEAR && wds_receve->role == MODE_AP) {
			if (!strncmp(wds_receve->bssid,ath_info_p.ath_mac,MAC_LEN)) {
				cpe_ap_sync_unlock_led(wds_receve->cpe_num,SYNC_CLEAR);
				//DEBUG("get root SYNC_CLEAR");
			}
			return;
		}

		if (wds_receve->sync_flag == SYNC_KEEP_LIVE && wds_receve->role == MODE_AP) {
			//if (memcmp(ath_mac,packet,6) == 0) {
				wds_link_status = 1;
				wds_sn_mac_update_info_pair_from_ap(wds_receve->wds_len,(char *)wds_receve->wds_sn_man_info);
				DEBUG("get root keep live date");
				dump_date(packet + 6,6);
			//}
			return;
		}
	} else {
		if (wds_receve->sync_flag == SYNC_KEEP_LIVE  && wds_receve->role == MODE_CPE) {
			//if (memcmp(ath_mac,packet,6) == 0) {
				DEBUG("get cpe keep live date");
				dump_date(packet + 6,6);
				wds_sn_mac_update_info_pair_from_cpe(wds_receve->wds_sn_man_info);
				wds_send_keep_date(packet + 6);
				wds_link_status = 1;
			//}
			return;
		}
	}
}

int reload_wifi(char reason)
{
	char buf[30];
	if (managed_ath() >=1 && (reason == WIFI_RELOAD_REASON_CHECK)) {
		memset(buf,0,sizeof(buf));
		sprintf(buf,"ifconfig %s down",ath_info_p.ath_name);
		system(buf);
		DEBUG("can not reboot ,sta is still assoc!,just do down ");
		sleep(10);
		memset(buf,0,sizeof(buf));
		sprintf(buf,"ifconfig %s up",ath_info_p.ath_name);
		system(buf);
		DEBUG("can not reboot ,sta is still assoc!,just do up ");
		return FAIL;
	}

	sleep(1);
	system("wifi &");
	DEBUG("");
	sleep(15);
	return SUCESS;
}

int ap_mode_change(char mode)
{
	int ret = SUCESS;

	DEBUG("mode %d",mode);

	if (mode == MODE_AP) {
		//如果配置已经是的话，就不需要修改了
		set_uci_config("wifi-iface","wds","mode",MODE_VALUE_AP,UCI_ATTRI_OPTION);

	} else {
		//如果配置已经是的话，就不需要修改了
		set_uci_config("wifi-iface","wds","mode",MODE_VALUE_CPE,UCI_ATTRI_OPTION);

	}

	set_uci_config("wifi-iface","wds","macfilter","",UCI_ATTRI_OPTION);
	set_uci_config("wifi-iface","wds","maclist","",UCI_ATTRI_LIST);
	//同时删除BSSID
	set_uci_config("wifi-iface","wds","bssid","",UCI_ATTRI_OPTION);

	reload_wifi(WIFI_RELOAD_REASON_MODE);
	get_athinfo();

	//wds_sn_mac_init();
	//wds_set_lock_mode();
	wds_sn_mac_clear_date();
	wds_sn_mac_create_file_all(1);
	wds_sn_mac_init();
}

int rm_enter_key(char *buf,int len) {
	int i;
	for (i = 0;i < len;i++) {
		if (buf[i] == '\n') {
			buf[i] = 0;
		}
	}
}

int get_bssid(char *bssid,int bssid_len) {
	FILE *p_ath;
	FILE *p_wds;
	FILE *p_bssid;
	char buf[100];
	char buf_2[100];
	int i ;
	char *p;
	char wds_flag = 0;
	int ret = SUCESS;

	if((p_ath = popen("ls /sys/class/net/ | grep ath", "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return FAIL;
	}

	memset(buf,0,sizeof(buf));
	while(fgets(buf, sizeof(buf), p_ath)){
		if (wds_flag) {
			break;
		}
		rm_enter_key(buf,strlen(buf));

        memset(buf_2,0,sizeof(buf_2));
        sprintf(buf_2,"iwpriv %s get_wds",buf);
		if((p_wds = popen(buf_2, "r")) == NULL) {
			printf("%s %d fail/n",__func__,__LINE__);
			ret = FAIL;
			break;
		}

		memset(buf_2,0,sizeof(buf_2));
		while (fgets(buf_2, sizeof(buf_2), p_wds)) {
			p = strtok(buf_2,":");
			while (p != NULL) {
				wds_flag = atoi(p);
				if (wds_flag) {
					//获取bssid
					memset(buf_2,0,sizeof(buf_2));
					sprintf(buf_2,"iwconfig %s | grep \"Access Point\" | awk \'{print $6}\'",buf);
					//DEBUG("buf_2 %s",buf_2);
					if((p_bssid = popen(buf_2, "r")) == NULL) {
						printf("%s %d fail/n",__func__,__LINE__);
						ret = FAIL;
						break;
					}
					memset(buf_2,0,sizeof(buf_2));
					while (fgets(bssid, bssid_len, p_bssid)) {
						//DEBUG("bssid %s",bssid);
						rm_enter_key(bssid,strlen(bssid));
						//DEBUG("bssid %s len %d ",bssid,strlen(bssid));
						if (strlen(bssid) == MAC_LEN) {
							ret = SUCESS;
							break;
						}
					}
					pclose(p_bssid);
					break;
				}
				p = strtok(NULL,":");
			}
		}
		pclose(p_wds);

	}
	pclose(p_ath);

	return ret;
}

int get_bssid_list(char *bssid_list)
{
	FILE *p_ath;
	FILE *p_wds;
	FILE *p_bssid;
	char buf[100];
	char buf_2[100];
	int i ;
	char *p;
	char wds_flag = 0;
	int count = 0;
	char bssid[20];

	if((p_ath = popen("ls /sys/class/net/ | grep ath", "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return FAIL;
	}

	memset(buf,0,sizeof(buf));
	while(fgets(buf, sizeof(buf), p_ath)){
		if (wds_flag) {
			break;
		}
		rm_enter_key(buf,strlen(buf));

        memset(buf_2,0,sizeof(buf_2));
        sprintf(buf_2,"iwpriv %s get_wds",buf);
		if((p_wds = popen(buf_2, "r")) == NULL) {
			printf("%s %d fail/n",__func__,__LINE__);
			break;
		}

		memset(buf_2,0,sizeof(buf_2));
		while (fgets(buf_2, sizeof(buf_2), p_wds)) {
			p = strtok(buf_2,":");
			while (p != NULL) {
				wds_flag = atoi(p);
				if (wds_flag) {
					//获取bssid
					memset(buf_2,0,sizeof(buf_2));
					sprintf(buf_2,"wlanconfig %s list | awk \'{print $1}\'",buf);
					//sprintf(buf_2,"wlanconfig %s list",buf);
					if((p_bssid = popen(buf_2, "r")) == NULL) {
						printf("%s %d fail/n",__func__,__LINE__);
						break;
					}
					memset(buf_2,0,sizeof(buf_2));
					memset(bssid,0,sizeof(bssid));
					while (fgets(bssid, sizeof(bssid), p_bssid)) {
						rm_enter_key(bssid,strlen(bssid));
						if (strlen(bssid) == MAC_LEN) {
							//DEBUG("bssid %s len %d ",bssid,strlen(bssid));
							memcpy(bssid_list + 17*count,bssid,MAC_LEN);
							count++;
						}
						memset(bssid,0,sizeof(bssid));
					}
					pclose(p_bssid);
					break;
				}
				p = strtok(NULL,":");
			}
		}
		pclose(p_wds);

	}
	pclose(p_ath);

	return count;
}

int ap_lock_change(char lock)
{
	int ret = SUCESS;
	char buf[256];
	char buf_2[50];
	char bssid[20];
	char ssid[33];
	char count;
	int i;

	memset(buf,0,sizeof(buf));
	memset(ssid, 0, sizeof(ssid));
	load_uci_config("wifi-iface", "wds", "ssid", buf, sizeof(buf));
	wds_set_lock_mode();

	if (lock == LOCK) {
		load_uci_config("wifi-iface","wds","ssid",ssid,sizeof(ssid));
		//DEBUG("wds.ssid %s",ssid);
		count = get_bssid_list(buf);
		//DEBUG("bssid_list %s",buf);
		//添加白名单
		//读到关联列表中已存在bssid或maclist，则进行设置uci
		if (!strcmp(ssid, (char *)&DEF_SSID) && count != 0) {
			if (value[0] == MODE_AP) {
				set_uci_config("wifi-iface","wds","macfilter","allow",UCI_ATTRI_OPTION);
				memset(buf_2,0,sizeof(buf_2));
				sprintf(buf_2,"iwpriv %s maccmd 1",ath_info_p.ath_name);
				system(buf_2);
				memset(buf_2,0,sizeof(buf_2));
				sprintf(buf_2,"iwpriv %s maccmd 3",ath_info_p.ath_name);
				system(buf_2);

				set_uci_config("wifi-iface","wds","maclist","",UCI_ATTRI_LIST);
				//wds_sn_mac_create_file(buf,count,1);
				DEBUG("");
				wds_sn_mac_create_file_all(1);
				DEBUG("");
				for (i = 0;i < count;i++) {
					memset(bssid,0,sizeof(bssid));
					memcpy(bssid,buf + i*17,17);
					//DEBUG("bssid %s",bssid);
					set_uci_config("wifi-iface","wds","maclist",bssid,UCI_ATTRI_LIST);
					memset(buf_2,0,sizeof(buf_2));
					sprintf(buf_2,"iwpriv %s addmac %s",ath_info_p.ath_name,bssid);
					system(buf_2);
				}
			} else {
				set_uci_config("wifi-iface","wds","bssid","",UCI_ATTRI_OPTION);
				for (i = 0;i < count;i++) {
					if (strlen(buf) == MAC_LEN) {
						//先清空
						memset(bssid,0,sizeof(bssid));
						memcpy(bssid,buf + i*17,17);

						set_uci_config("wifi-iface","wds","bssid",bssid,UCI_ATTRI_OPTION);
						//立即生效
						//memset(buf_2,0,sizeof(buf_2));
						//sprintf(buf_2,"iwconfig %s ap %s",ath_info_p.ath_name,bssid);
						//system(buf_2);
						//DEBUG("buf_2 %s",buf_2);
					} else {
						printf("can not find the bssid\n");
					}
				}
			}
			cpe_ap_sync_unlock_led(0,SYNC_CLEAR);
		} else {
			/*
			 *	1、关联列表中不存在bssid或maclist，则清空uci配置中相应的设置；
			 *	2、锁定时，桥接ssid不为缺省值，清空相应的配置；
			 */
			/* AP */
			set_uci_config("wifi-iface","wds","macfilter","",UCI_ATTRI_OPTION);
			set_uci_config("wifi-iface","wds","maclist","",UCI_ATTRI_LIST);
			memset(buf_2,0,sizeof(buf_2));
			sprintf(buf_2,"iwpriv %s maccmd 0",ath_info_p.ath_name);
			system(buf_2);

			/* CPE */
			set_uci_config("wifi-iface","wds","bssid","",UCI_ATTRI_OPTION);
			system("uci commit wireless");
		}
	} else {
		/* AP */
		set_uci_config("wifi-iface","wds","macfilter","",UCI_ATTRI_OPTION);
		set_uci_config("wifi-iface","wds","maclist","",UCI_ATTRI_LIST);
		memset(buf_2,0,sizeof(buf_2));
		sprintf(buf_2,"iwpriv %s maccmd 0",ath_info_p.ath_name);
		system(buf_2);

		/* CPE */
		set_uci_config("wifi-iface","wds","bssid","",UCI_ATTRI_OPTION);
		reload_wifi(WIFI_RELOAD_REASON_UNLOCK);
		wds_sn_mac_clear_date();
		wds_sn_mac_clear_file(1);
	}
}


int gpio_value_change(char gpio,char value)
{
	int i = 0;
	DEBUG("gpio %d value %d",gpio,value);
	switch (gpio) {
		case MODE_GPIO:
			switch (value) {
				case MODE_AP:
					ap_mode_change(MODE_AP);
					break;
				case MODE_CPE:
					ap_mode_change(MODE_CPE);
					break;
			}
			break;
		case LOCK_GPIO:
			switch (value) {
				case LOCK:
					ap_lock_change(LOCK);
					break;
				case UNLOCK:
					ap_lock_change(UNLOCK);
					break;
			}
			break;
	}
	return SUCESS;
}

int gpio_edge_change(char gpio,char value)
{
	char str_buffer[120];
	char *rising="rising";
	char *falling="falling";
	char *edge;
	int fd;

	DEBUG("gpio %d value %d",gpio,value);

	memset(str_buffer,0,sizeof(str_buffer));
	sprintf(str_buffer,"/sys/class/gpio/gpio%d/edge",gpio);
	if (value == 1) {
		edge = falling;
	} else {
		edge = rising;
	}

	DEBUG("str_buffer %s edge %s",str_buffer,edge);
    if ((fd = open(str_buffer,O_WRONLY) ) < 0 ) {
        printf("open file %s error",str_buffer);
        return -1;
    }

    write(fd,edge,strlen(edge));
    close(fd);
}

int gpio_init()
{
	int i;
	DEBUG("");
	char ap_mode[256];
	char lock_bssid[100];
	char wds_ssid[33];
	char gpio_ap_mode_last;
	char gpio_lock_last;
	char flag = 0;

	memset(ap_mode,0,sizeof(ap_mode));
	memset(lock_bssid,0,sizeof(lock_bssid));

	load_uci_config("wifi-iface","wds","mode",ap_mode,sizeof(ap_mode));
	load_uci_config("wifi-iface","wds","bssid",lock_bssid,sizeof(lock_bssid));

	DEBUG("uci ap_mode %s",ap_mode);
	DEBUG("uci lock_bssid %s",lock_bssid);

	if (!strcmp(ap_mode,MODE_VALUE_AP)) {
		gpio_ap_mode_last = MODE_AP;
	} else if (!strcmp(ap_mode,MODE_VALUE_CPE)) {
		gpio_ap_mode_last = MODE_CPE;
	}

	//下电的时候AP 和 STA 状态发生改变
	DEBUG("gpio_ap_mode_last %d value[0] %d",gpio_ap_mode_last,value[0]);
	if (gpio_ap_mode_last != value[0]) {
		gpio_value_change(gpio[0],value[0]);
	}

	// ULOCK状态下启动进程
	if (value[1] == UNLOCK) {
		memset(ap_mode,0,sizeof(ap_mode));
		load_uci_config("wifi-iface","wds","macfilter",ap_mode,sizeof(ap_mode));
		DEBUG("ap_mode %s",ap_mode);
		if (strlen(ap_mode) != 0) {
			flag = 1;
		}

		memset(ap_mode,0,sizeof(ap_mode));
		load_uci_config("wifi-iface","wds","maclist",ap_mode,sizeof(ap_mode));
		DEBUG("ap_mode %s",ap_mode);
		if (strlen(ap_mode) != 0) {
			flag = 1;
		}

		memset(ap_mode,0,sizeof(ap_mode));
		load_uci_config("wifi-iface","wds","bssid",ap_mode,sizeof(ap_mode));
		DEBUG("ap_mode %s",ap_mode);
		if (strlen(ap_mode) != 0) {
			flag = 1;
		}
		if (flag == 1) {
			//AP
			set_uci_config("wifi-iface","wds","macfilter","",UCI_ATTRI_OPTION);
			set_uci_config("wifi-iface","wds","maclist","",UCI_ATTRI_LIST);
			//CPE
			set_uci_config("wifi-iface","wds","bssid","",UCI_ATTRI_OPTION);
			reload_wifi(WIFI_RELOAD_REASON_MODE);
		}
	}
	///*
	//*/
	get_athinfo();
	wds_sn_mac_init();
	memset(ap_mode,0,sizeof(ap_mode));
	load_uci_config("wifi-iface", "wds", "maclist", ap_mode, sizeof(ap_mode));
	if (strlen(ap_mode) > 0) {
		wds_sn_mac_read_info();
		wds_sn_mac_create_file_all(0);
	}
	DEBUG("gpio_ap_mode_last %d now %d gpio_lock_last %d now %d",gpio_ap_mode_last,value[0],gpio_lock_last,value[1]);
}

int process_wds_gpio()
{
	int gpio_fd, ret;
	struct pollfd fds[2];
	char buff[10];
	unsigned char cnt = 0;
	char str_buffer[120];
	char value_tmp;

	int i;

	for (i = 0;i < sizeof(gpio);i++) {
		memset(str_buffer,0,sizeof(str_buffer));
		sprintf(str_buffer,"/sys/class/gpio/gpio%d/value",gpio[i]);
		DEBUG("str_buffer %s",str_buffer);
		gpio_fd = open(str_buffer,O_RDONLY);

		if (gpio_fd < 0) {
			printf("Failed to open value! \n");
			return -1;
		}

		fds[i].fd = gpio_fd;
		fds[i].events  = POLLPRI;

		memset(buff,0,sizeof(buff));
		ret = read(gpio_fd,buff,sizeof(buff));
		if (ret > -0) {
			DEBUG("buff %s",buff);
			value[i] = atoi(buff);
			gpio_edge_change(gpio[i],value[i]);
		}
	}

	gpio_init();
	while (1) {
		ret = poll(fds,2,-1);
		if ( ret == -1 ) {
			printf("poll\n");
			sleep(1);
			continue;
		}
		for (i = 0;i < sizeof(gpio);i++) {
			if (fds[i].revents & POLLPRI) {
				ret = lseek(fds[i].fd,0,SEEK_SET);
				if (ret == -1) {
					printf("lseek\n");
					sleep(1);
					continue;
				}
				sleep(1);
				memset(buff,0,sizeof(buff));
				ret = read(fds[i].fd,buff,sizeof(buff));
				value_tmp = atoi(buff);
				if (ret > 0) {
					DEBUG("gpio %d value %d \n",gpio[i],value_tmp);
					if (value[i] != value_tmp) {
						value[i] = value_tmp;
						gpio_edge_change(gpio[i],value[i]);
						gpio_value_change(gpio[i],value[i]);
					}
				}
			}
		}
	}

	return 0;

}

int main()
{
	pthread_t thread_wds_gpio;
	pthread_t thread_wds_led_sync;
	pthread_t thread_wds_link_keep;

	
	//开启WDS GPIO捕抓线程
	if (0 != pthread_create(&thread_wds_gpio,NULL,process_wds_gpio,NULL)) {
		printf("%s %d error \n",__func__,__LINE__);
	}
	///*
	//LED同步链路检查
	if (0 != pthread_create(&thread_wds_led_sync,NULL,process_sync_unlock_led,NULL)) {
		printf("%s %d error \n",__func__,__LINE__);
	}
	///*
	if (0 != pthread_create(&thread_wds_link_keep,NULL,process_link_check,NULL)) {
		printf("%s %d error \n",__func__,__LINE__);
	}
	//*/
	//*/
	wds_revece_pactek();
}
