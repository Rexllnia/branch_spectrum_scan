#include "rg_wds.h"
#include "rg_wds_pair_assioc.h"
#include <errno.h>
#include "was_sdk.h"
char reload_wifi_count = 0;
unsigned long last_data_time = 0;
extern unsigned char fast_wds_flag;
extern unsigned char wds_fast_keep_live_flag;

static u_int ieee80211_mhz2ieee(u_int freq)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)

	if (freq == 2484)
        return 14;
    if (freq < 2484)
        return (freq - 2407) / 5;
    if (freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
            return ((freq * 10) +
                (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
        } else if (freq > 4900) {
            return (freq - 4000) / 5;
        } else {
            return 15 + ((freq - 2512) / 20);
        }
    }
    return (freq - 5000) / 5;
}

static const char *ieee80211_ntoa(const uint8_t mac[IEEE80211_ADDR_LEN])
{
	static char a[18];
	int i;

	i = snprintf(a, sizeof(a), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (i < 17 ? NULL : a);
}

void rg_wds_rst_kpl_param(void)
{
    reload_wifi_count = 0;
    last_data_time = 0;
}

struct pair_dev_ath_info * rg_wds_find_inode(char *mac)
{
	struct pair_dev_ath_info * p = rg_pair_info_heap_t;

	while (p) {
		if (memcmp(mac,p->mac,6) == 0) {
			return p;
		}
		p = p->next;
	}
	return NULL;
}

void rg_wds_pair_add(struct pair_dev_ath_info * pair_p)
{
	struct pair_dev_ath_info * p;
	struct pair_dev_ath_info * pl;

	if (rg_pair_info_heap_t == NULL) {
		GPIO_DEBUG("rg_pair_info_heap_t == NULL");
		rg_pair_info_heap_t = pair_p;
		return;
	}

	p = rg_pair_info_heap_t;
	while (p) {
		pl = p;
		p = p->next;
	}

	pl->next = pair_p;
	GPIO_DEBUG("add mac pair_p");
	dump_date(pair_p->mac,6);
	return;
}

void del_pw_state_right_node(void){
	int member_index;
	char sys_mac_tmp[18];
	struct pair_dev_ath_info *pair_tmp = rg_pair_info_heap_t;
	if (rg_ath_info_t.role == MODE_CPE){
		memset(sys_mac_tmp, 0, sizeof(sys_mac_tmp));
		if (rg_wds_misc_read_file("/tmp/.ap_sysmac", sys_mac_tmp, sizeof(sys_mac_tmp)) == FAIL) {
			GPIO_DEBUG("read /tmp/.ap_sysmac fail!!!");
		}
		if (strlen(sys_mac_tmp)) {
			member_index =wds_pw_arr_find_node(sys_mac_tmp);
			if (member_index != -1){
				GPIO_DEBUG("===mac:%s wds_pw right so delete",sys_mac_tmp);
				wds_pw_arr_del(member_index);
			}
		}
	}else{
		pthread_mutex_lock(&rg_pair_mtx);
		while (pair_tmp) {
			memset(sys_mac_tmp, 0, sizeof(sys_mac_tmp));
			sprintf(sys_mac_tmp, "%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC(pair_tmp->pair_dev_info_t.sys_mac));
			member_index =wds_pw_arr_find_node(sys_mac_tmp);
			if (member_index != -1){
				GPIO_DEBUG("===mac:%02x:%02x:%02x:%02x:%02x:%02x wds_pw right so delete",pair_tmp->pair_dev_info_t.sys_mac);
				wds_pw_arr_del(member_index);
				break;
			}
			pair_tmp = pair_tmp->next;
		}
		pthread_mutex_unlock(&rg_pair_mtx);
	}
}

int wds_ath_dev_ioctl(char *devname, int cmd, void *buf)
{
    int skfd;
    int ret;
    struct ifreq *ifr;

    if (devname == NULL || buf == NULL) {
        printf("dev ioctl param error\n");
        return -WAS_E_PARAM;
    }

    ret = WAS_E_NONE;
    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket create failed\n");
        return -WAS_E_FAIL;
    }

    ifr = (struct ifreq *)buf;
    strncpy(ifr->ifr_name, devname, IFNAMSIZ);
    ifr->ifr_name[IFNAMSIZ - 1] = '\0';
    ret = ioctl(skfd, cmd, ifr);
    if (ret != 0) {
        if (ret < 0) {
            ret = -WAS_E_FAIL;
        } else {
        }
    }
    close(skfd);

    return ret;
}

int wds_ath_wl_handler(char *devname, int cmd, void *buf)
{
    int skfd;
    int ret;
    struct iwreq *wrq;

    if (devname == NULL || buf == NULL) {
        printf("wl handler param error\n");
        return -WAS_E_PARAM;
    }
    ret = WAS_E_NONE;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket create failed\n");
        return -WAS_E_FAIL;
    }

    wrq = (struct iwreq *)buf;
    strncpy(wrq->ifr_name, devname, IFNAMSIZ);
    wrq->ifr_name[IFNAMSIZ - 1] = '\0';
    ret = ioctl(skfd, cmd, wrq);
    if (ret != 0) {
        if (ret < 0) {
            //GPIO_DEBUG("ret(%d): %s  no private ioctls.[%s]", ret, devname, strerror(ret));
            ret = -WAS_E_FAIL;
        } else {
            //GPIO_DEBUG("ret(%d): %s", ret, strerror(ret));
        }
    }
    close(skfd);

    return ret;
}


int wds_radio_param_op(char *devname, int cmd, void *buf, bool standard)
{
    int ret;

    if (standard) {
        ret = wds_ath_dev_ioctl(devname, cmd, buf);
    } else {
        ret = wds_ath_wl_handler(devname, cmd, buf);
    }

    return ret;
}

int save_pair_info_to_list(rj_stainfo_t *asso_info){
	unsigned char pair_mac[6];
	const char *ath_mac = NULL;
	struct sysinfo info;
	
	struct pair_dev_ath_info * pair_link_tmp = NULL;
	
	if(!asso_info){
		GPIO_DEBUG("%s():asso_info is NULL!!!", __FILE__);
		return;
	}

	memset(pair_mac, 0, sizeof(pair_mac));
	if(MODE_CPE == rg_ath_info_t.role){
		memcpy(pair_mac, asso_info->bssid, 6);
	}else if(MODE_AP == rg_ath_info_t.role) {
		memcpy(pair_mac, asso_info->mac, 6);
	}
	
	//Get association info
	
	ath_mac = ieee80211_ntoa(pair_mac);
	GPIO_DEBUG("peer_mac:%s", ath_mac);
	
	if (!strcmp(ath_mac, "00:00:00:00:00:00")) {
		return FAIL;
	}
	
	pair_link_tmp = rg_wds_find_inode(pair_mac);
	if (NULL == pair_link_tmp) {
		pair_link_tmp = malloc(sizeof(struct pair_dev_ath_info));
		if (pair_link_tmp != NULL) {
			memset(pair_link_tmp, 0, sizeof(struct pair_dev_ath_info));
			memcpy(pair_link_tmp, pair_mac, 6);
			rg_wds_pair_add(pair_link_tmp);
		} else {
			GPIO_ERROR("Malloc asso info space fail!!!");
			return FAIL;
		}
	}
	pair_link_tmp->pair_assioc_info_t.rssi = asso_info->rssi;
	pair_link_tmp->pair_assioc_info_t.rxrate = asso_info->sta_rxrate; //* 1024;
	pair_link_tmp->pair_assioc_info_t.txrate = asso_info->sta_txrate; //* 1024;
	pair_link_tmp->pair_assioc_info_t.assioc_time = asso_info->assoctime_val;
	//GPIO_DEBUG("cpe assioc time:%d", asso_info->assoctime_val);
   	pair_link_tmp->pair_assioc_info_t.channel = asso_info->channel; //ieee80211_mhz2ieee(si->isi_freq);
   	//GPIO_DEBUG("cpe assoc channel:%d", asso_info->channel);
	pair_link_tmp->pair_assioc_info_t.BW = 0;
	//memset(pair_link_tmp->pair_assioc_info_t.BW,0,sizeof(pair_link_tmp->pair_assioc_info_t.phymode));
    pair_link_tmp->pair_assioc_info_t.BW = asso_info->BW;
    //pair_link_tmp->pair_assioc_info_t.phymode = phy
	GPIO_DEBUG("cpe assoc BW:%d assoc channel:%d assioc time:%d ",asso_info->BW,asso_info->channel,asso_info->assoctime_val);
	sysinfo(&info);
	pair_link_tmp->time_newest = info.uptime;

	return SUCESS;
}
int cpe_assoc_state(rj_stainfo_t *asso_info){
	int state_res = FAIL;
	
	if(asso_info->is_reassoc){
		state_res = SUCESS;
	}

	return state_res;
}

int ap_assoc_state(rj_stainfo_t *asso_info){
	int state_res = FAIL;
	if(asso_info->assoctime_val > 10){
		state_res = SUCESS;
	}

	return state_res;
}

int assoc_state( rj_stainfo_t *assoc_info, int dev_num){
	int state_res = FAIL;
	int i=0;
	
	if(MODE_CPE == rg_ath_info_t.role){
		state_res = cpe_assoc_state(assoc_info);
	}else if(MODE_AP == rg_ath_info_t.role){
		for(i=0; i<dev_num; i++){
			state_res = ap_assoc_state(&assoc_info[i]);
		}

		if(0==i){
			GPIO_DEBUG("invalid sta number");
		}else if(FAIL==state_res){
			GPIO_DEBUG("The association time of all STAs is less than 10 seconds");
		}
	}
	
	return state_res;
}

int save_pair_info(int dev_num, void* buf){
	int i =0,member_index = 0;
	const char *ath_mac = NULL;
	unsigned char pair_mac[6];
	rj_stainfo_t *asso_info = NULL;
	RJ80211_MAC_TABLE *asso_info_mac_table = NULL;
	int ap_assoc_state;
	
	if(!buf){
		GPIO_ERROR("%s:buf is null!", __func__);
		return FAIL;
	}
	
	if(MODE_CPE == rg_ath_info_t.role){
		asso_info = (rj_stainfo_t *)buf;	
	}else if(MODE_AP == rg_ath_info_t.role){
		asso_info_mac_table = (RJ80211_MAC_TABLE *)buf;
    	asso_info = (rj_stainfo_t *)&asso_info_mac_table[1];		
	}

	if(FAIL == assoc_state(asso_info, dev_num)){
		return FAIL;
	}
	
	for (i=0; i<dev_num; i++) {	
		save_pair_info_to_list(&asso_info[i]);
	}

	return SUCESS;
	
}

int rg_wds_pair_list_stations(const char *ifname)
{
	rj_ex_ioctl_t ioc;
	rj_stainfo_t stainfo;
	void *asso_info = NULL;
	int ret = 0, sta_num = 0;
	char devname[IFNAMSIZ];
    char msg[MAC_TAB_LEN];
	int msg_len = sizeof(msg);
	int msg_type;
	RJ80211_MAC_TABLE *sta_info = NULL;

	memset(devname, 0, IFNAMSIZ);
    strncpy(devname, ifname, IFNAMSIZ - 1);
	
	if(MODE_CPE == rg_ath_info_t.role){
		msg_type = RJ_WAS_SHOW_APLCLI_INFO_EN;
		sta_num = 1;
	}else if(rg_ath_info_t.role == MODE_AP){
		memset(msg, 0, msg_len);
		if (was_ext_ioctl_msg(msg, MAC_TAB_LEN, ifname, RJ_WAS_GET_STANUM_EN, false) != 0) {
            GPIO_DEBUG("get sta num fail");
            return FAIL;
        }
		
		sta_num = atoi(msg);
		GPIO_DEBUG("get_sta_num=%d", sta_num);
		
		memset(msg, 0, msg_len);
		sta_info = (RJ80211_MAC_TABLE *)msg;
		sta_info->Num = sta_num;
		sta_info->expFlag = WAS_GET_STAINFO;
		
		msg_type = RJ_WAS_GET_STAINFO_EN;
	}else{
		GPIO_ERROR("dev role UNKNOWN");
		return FAIL;
	}	

	ret = was_ext_ioctl_msg(msg, msg_len, ifname, msg_type, false);
    if (ret != WAS_E_NONE) {
        GPIO_DEBUG("wlanconfig result is failed");
       	return FAIL;
    }
	
	//Save association to self link
    return save_pair_info(sta_num, msg);
}	

char rg_wds_pair_offline(struct pair_dev_ath_info * p) {
	struct sysinfo info;

	sysinfo(&info);
	if ((info.uptime -  p->time_newest) > WLANCONFIG_LIST_OFF_TIME) {
		return 1;
	}
	return 0;
}

char rg_wds_pair_list_len() {
	struct pair_dev_ath_info * p = rg_pair_info_heap_t;
	char len = 0;
	while (p) {
		len++;
		p = p->next;
	}

	return len;
}

//删除过时设备
void rg_wds_pair_list_update() {
	struct pair_dev_ath_info * p = rg_pair_info_heap_t;
	struct pair_dev_ath_info * pl;
	struct sysinfo info;

	if (p == NULL) {
		return;
	}

	sysinfo(&info);
	while (p) {
		//pl = p->next;
		//超时，且设备的节点不在白名单中，则删除该节点
		GPIO_DEBUG("maclist_flag==%d   now time:%d, time_newest:%d, off time:%d", p->maclist_flag,info.uptime, p->time_newest, info.uptime-p->time_newest);
		if (p->maclist_flag == 0 && (info.uptime -  p->time_newest) > WLANCONFIG_LIST_OFF_TIME) {
			GPIO_DEBUG("del pair mac ");
            GPIO_DEBUG("DEL REDBS RSSI TABLE:%02x:%02x:%02x:%02x:%02x:%02x",PRINT_MAC(p->mac));
            redbs_wds_rssi_del_pub(p->mac);
			//删除头节点
			if (p == rg_pair_info_heap_t) {
				//待从头、收拾旧山河，朝天阙
				rg_pair_info_heap_t = p->next;
				free(p);
				p = rg_pair_info_heap_t;
				continue;
			} else if (p->next == NULL) {
				//删除最后一个节点,上一个节点的后续节点设置为NULL
				free(p);
				pl->next = NULL;
				return;
			} else {
				//删除中间节点,上一个节点的下标指向当前节点的下一个节点
				pl->next = p->next;
				free(p);
				p = pl->next;
			}
		}
	loop:
		pl = p;
		p = p->next;
	}
}


char rg_wds_pair_all_offline() {
	struct sysinfo info;
	sysinfo(&info);
	static unsigned char fast_wds_count = 0;
 
	if (last_data_time == 0) {
		last_data_time = info.uptime;
	}
	pthread_mutex_lock(&wds_fast_pair_mtx);
	if ((fast_wds_flag == 1)&&(wds_fast_keep_live_flag == 0)) {		/* 一键易联&&扫描配对中禁止重启 */
		if (fast_wds_count > WDS_FAST_FLAG_KEEP_LIVE){
				wds_fast_keep_live_flag = 1;
				fast_wds_count = 0;
				GPIO_FILE("fast_wds_count > WDS_FAST_FLAG_KEEP_LIVE\n");
			}/* 三分钟后放行 */	
		fast_wds_count++;
		pthread_mutex_unlock(&wds_fast_pair_mtx);
		return;
	}else{
		fast_wds_count = 0;
	}
	pthread_mutex_unlock(&wds_fast_pair_mtx);
	if (rg_pair_info_heap_t == NULL) {
		//GPIO_DEBUG("rg_pair_info_heap_t == NULL,last_data_time %d reload_wifi_count %d uptime %d ",last_data_time,reload_wifi_count,info.uptime);
		if (rg_ath_info_t.role == MODE_AP) {
			if (info.uptime - last_data_time > WDS_KEEP_WIFI_ROOT_RELOAD) {
				last_data_time = info.uptime;
				reload_wifi_count++;
				if (reload_wifi_count == WDS_KEEP_WIFI_ROOT_REBOOT) {
					reload_wifi_count = 0;
					return REBOOT_DEV;		//If the AP is disconnected for 2 hour, restart the device
				} else {
					return REBOOT_WIFI;		//If the AP is disconnected for 20 min, restart the WiFi
				}
			}
		} else {
			if (info.uptime - last_data_time > WDS_KEEP_WIFI_RELOAD) {
				last_data_time = info.uptime;
				reload_wifi_count++;
				if (reload_wifi_count == WDS_KEEP_WIFI_REBOOT) {
					reload_wifi_count = 0;
					return REBOOT_DEV;		//If the CPE is disconnected for 1 hour, restart the device
				} else {
					return REBOOT_WIFI;		//If the CPE is disconnected for 10 min, restart the WiFi
				}
			}
		}
	}

	if (rg_pair_info_heap_t != NULL) {
		//GPIO_DEBUG("%s() rg_pair_info_heap_t !!!!= NULL, last_data_time %d reload_wifi_count %d uptime %d ", __FILE__, last_data_time,reload_wifi_count,info.uptime);
		struct pair_dev_ath_info * p = rg_pair_info_heap_t;
		unsigned long data_time_tmp = 0;
		while (p) {
			if (p->pair_keep_info_t.pair_live_get_time > data_time_tmp) {
				data_time_tmp = p->pair_keep_info_t.pair_live_get_time;
			}
			p = p->next;
		}
		if (data_time_tmp > last_data_time) {
			last_data_time = data_time_tmp;
			reload_wifi_count = 0;
		} else {
			if (rg_ath_info_t.role == MODE_AP) {
				if (info.uptime - last_data_time > WDS_KEEP_WIFI_ROOT_RELOAD) {
					last_data_time = info.uptime;
					reload_wifi_count++;
					if (reload_wifi_count == WDS_KEEP_WIFI_ROOT_REBOOT) {
						reload_wifi_count = 0;
						return 2;
					} else {
						return 1;
					}
				}
			} else {
				if (info.uptime - last_data_time > WDS_KEEP_WIFI_RELOAD) {
					last_data_time = info.uptime;
					reload_wifi_count++;
					if (reload_wifi_count == WDS_KEEP_WIFI_REBOOT) {
						reload_wifi_count = 0;
						return 2;
					} else {
						return 1;
					}
				}
			}
		}
	}

	return 0;
}

void rg_wds_pair_reboot() {
    char ret;
    ret = rg_wds_pair_all_offline();
    if (ret == REBOOT_WIFI) {
        //重启wifi
        GPIO_DEBUG("keep live can not recevice data !! reload wifi");
        rg_wds_ath_reload_wifi();
    } else if (ret == REBOOT_DEV) {
        //没招了，只能重启设备
        GPIO_DEBUG("keep live can not recevice data !! reboot dev");
        rg_wds_dev_reboot();
    }
}

char rg_wds_show_pair_list()
{
	struct pair_dev_ath_info * p = rg_pair_info_heap_t;

	while (p) {
		printf("%s %d mac ",__func__,__LINE__);
		dump_date(p->mac,6);
		GPIO_DEBUG("rssi %d",p->pair_assioc_info_t.rssi);
		GPIO_DEBUG("rxrate %d",p->pair_assioc_info_t.rxrate);
		GPIO_DEBUG("rxrate %d",p->pair_assioc_info_t.rxrate);
		GPIO_DEBUG("send  %d",p->pair_keep_info_t.pair_live_send_num);
		GPIO_DEBUG("get %d",p->pair_keep_info_t.pair_live_get_num);
		GPIO_DEBUG("wlanconfig time  %d",p->time_newest);
		GPIO_DEBUG("keep live time  %d",p->pair_keep_info_t.pair_live_get_time);
		GPIO_DEBUG("version %d",p->version_flag);
		p = p->next;
	}
}

/*
char rg_wds_pair_init()
{
	//ap端读取maclist
	if (rg_ath_info_t.role == MODE_AP && rg_gpio_info_t.) {

	}
}
*/
