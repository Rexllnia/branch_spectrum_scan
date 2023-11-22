#include "rg_wds.h"
#include "rg_wds_pair_assioc.h"

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

struct pair_dev_ath_info * rg_wds_pair_check(char *mac)
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
		rg_pair_info_heap_t = pair_p;
		return;
	}

	p = rg_pair_info_heap_t;
	while (p) {
		pl = p;
		p = p->next;
	}

	pl->next = pair_p;
	DEBUG("add mac pair_p");
	dump_date(pair_p->mac,6);
	return;
}

void rg_wds_pair_list_stations(const char *ifname)
{
    uint8_t *buf;
    struct iwreq iwr;
    uint8_t *cp;
    int s;
    u_int32_t txrate, rxrate = 0, maxrate = 0;
    u_int32_t time_val=0, hour_val=0, min_val=0, sec_val=0;
    u_int64_t wifiup, wifidown = 0;
    const char *ntoa = NULL;
    int req_space = 0;
    u_int64_t len = 0;
    char *ieee80211_phymode_str[23] =  {
        "IEEE80211_MODE_AUTO",
        "IEEE80211_MODE_11A",
        "IEEE80211_MODE_11B",
        "IEEE80211_MODE_11G",
        "IEEE80211_MODE_FH",
        "IEEE80211_MODE_TURBO_A",
        "IEEE80211_MODE_TURBO_G",
        "IEEE80211_MODE_11NA_HT20",
        "IEEE80211_MODE_11NG_HT20",
        "IEEE80211_MODE_11NA_HT40PLUS",
        "IEEE80211_MODE_11NA_HT40MINUS",
        "IEEE80211_MODE_11NG_HT40PLUS",
        "IEEE80211_MODE_11NG_HT40MINUS",
        "IEEE80211_MODE_11NG_HT40",
        "IEEE80211_MODE_11NA_HT40",
        "IEEE80211_MODE_11AC_VHT20",
        "IEEE80211_MODE_11AC_VHT40PLUS",
        "IEEE80211_MODE_11AC_VHT40MINUS",
        "IEEE80211_MODE_11AC_VHT40",
        "IEEE80211_MODE_11AC_VHT80",
        "IEEE80211_MODE_11AC_VHT160",
        "IEEE80211_MODE_11AC_VHT80_80",
        (char *)NULL,
    };


	buf = malloc(LIST_STATION_ALLOC_SIZE);
	if (!buf) {
	  fprintf (stderr, "Unable to allocate memory for station list\n");
	  return;
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		free(buf);
		err(1, "socket(SOCK_DRAGM)");
	}

	if (!strncmp(ifname, "wifi", 4)) {
		free(buf);
		err(1, "Not a valid interface");
	}

	(void) memset(&iwr, 0, sizeof(iwr));
	if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
		fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
		free(buf);
		return;
	}

	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = LIST_STATION_ALLOC_SIZE;

    iwr.u.data.flags = 0;
    //Support for 512 client
    req_space = ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr);
	if (req_space < 0 ) {
		free(buf);
        close(s);
		return;
    }  else if(req_space > 0) {
        free(buf);
        buf = malloc(req_space);
        if(!buf) {
            fprintf (stderr, "Unable to allocate memory for station list\n");
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = req_space;
        if(iwr.u.data.length < req_space)
            iwr.u.data.flags = 1;
        if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0 ){
            free(buf);
            close(s);
            return;
        }
        len = req_space;

    } else {
        len = iwr.u.data.length;
    }

    if (len < sizeof(struct ieee80211req_sta_info)) {
        free(buf);
        close(s);
        return;
    }

	cp = buf;
	do {
		struct ieee80211req_sta_info *si;
		uint8_t *vp;
		struct pair_dev_ath_info * pair_list_p_tmp;
		struct sysinfo info;
		si = (struct ieee80211req_sta_info *) cp;
		time_val = si->isi_tr069_assoc_time.tv_sec;
	 	hour_val = time_val / 3600;
 	 	time_val = time_val % 3600;
 	 	min_val = time_val / 60;
 	 	sec_val = time_val % 60;
		vp = (u_int8_t *)(si+1);
        if(si->isi_txratekbps == 0) {
            txrate = (si->isi_rates[si->isi_txrate] & IEEE80211_RATE_VAL)/2;
        } else {
            txrate = si->isi_txratekbps / 1000;
        }

        if(si->isi_rxratekbps >= 0) {
            rxrate = si->isi_rxratekbps / 1000;
		}
        maxrate = si->isi_maxrate_per_client;

        if (maxrate & 0x80) maxrate &= 0x7f;
            ntoa = ieee80211_ntoa(si->isi_macaddr);
		if (ntoa != NULL) {
			pair_list_p_tmp = rg_wds_pair_check(si->isi_macaddr);
			if (pair_list_p_tmp != NULL) {
				pair_list_p_tmp->pair_assioc_info_t.rssi = si->isi_rssi;
				pair_list_p_tmp->pair_assioc_info_t.rxrate = rxrate;
				pair_list_p_tmp->pair_assioc_info_t.txrate = txrate;
				pair_list_p_tmp->pair_assioc_info_t.assioc_time = si->isi_tr069_assoc_time.tv_sec;
                pair_list_p_tmp->pair_assioc_info_t.channel = ieee80211_mhz2ieee(si->isi_freq);
                memset(pair_list_p_tmp->pair_assioc_info_t.phymode,0,sizeof(pair_list_p_tmp->pair_assioc_info_t.phymode));
                strcpy(pair_list_p_tmp->pair_assioc_info_t.phymode,(si->isi_stamode < 22)?ieee80211_phymode_str[si->isi_stamode]:"IEEE80211_MODE_11B");
            } else {
				pair_list_p_tmp = malloc(sizeof(struct pair_dev_ath_info));
				if (pair_list_p_tmp != NULL) {
					memset(pair_list_p_tmp,0,sizeof(struct pair_dev_ath_info));
					memcpy(pair_list_p_tmp,si->isi_macaddr,6);
					pair_list_p_tmp->pair_assioc_info_t.rssi = si->isi_rssi;
					pair_list_p_tmp->pair_assioc_info_t.rxrate = rxrate;
					pair_list_p_tmp->pair_assioc_info_t.txrate = txrate;
				    pair_list_p_tmp->pair_assioc_info_t.assioc_time = si->isi_tr069_assoc_time.tv_sec;
                    pair_list_p_tmp->pair_assioc_info_t.channel = ieee80211_mhz2ieee(si->isi_freq);
                    memset(pair_list_p_tmp->pair_assioc_info_t.phymode,0,sizeof(pair_list_p_tmp->pair_assioc_info_t.phymode));
                    strcpy(pair_list_p_tmp->pair_assioc_info_t.phymode,(si->isi_stamode < 22)?ieee80211_phymode_str[si->isi_stamode]:"IEEE80211_MODE_11B");
					rg_wds_pair_add(pair_list_p_tmp);
				}
			}

			if (pair_list_p_tmp != NULL) {
				sysinfo(&info);
				pair_list_p_tmp->time_newest = info.uptime;
			}
		}
		cp += si->isi_len, len -= si->isi_len;
	} while (len >= sizeof(struct ieee80211req_sta_info));

	free(buf);
    close(s);
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
		if (p->maclist_flag == 0 && (info.uptime -  p->time_newest) > WLANCONFIG_LIST_OFF_TIME) {
			DEBUG("del mac ");
			dump_date(p->mac,6);
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
	static char reload_wifi_count;
	static unsigned long last_data_time;
	sysinfo(&info);

	if (last_data_time == 0) {
		last_data_time = info.uptime;
	}

	if (rg_pair_info_heap_t == NULL) {
		//DEBUG("last_data_time %d reload_wifi_count %d uptime %d ",last_data_time,reload_wifi_count,info.uptime);
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

	if (rg_pair_info_heap_t != NULL) {
		//DEBUG("last_data_time %d reload_wifi_count %d uptime %d ",last_data_time,reload_wifi_count,info.uptime);
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
    if (ret == 1) {
        //重启wifi
        DEBUG("keep live can not recevice data !! reload wifi");
        rg_wds_ath_reload_wifi();
    } else if (ret == 2) {
        //没招了，只能重启设备
        DEBUG("keep live can not recevice data !! reboot dev");
        rg_wds_dev_reboot();
    }
}

char rg_wds_show_pair_list()
{
	struct pair_dev_ath_info * p = rg_pair_info_heap_t;

	while (p) {
		printf("%s %d mac ",__func__,__LINE__);
		dump_date(p->mac,6);
		DEBUG("rssi %d",p->pair_assioc_info_t.rssi);
		DEBUG("rxrate %d",p->pair_assioc_info_t.rxrate);
		DEBUG("rxrate %d",p->pair_assioc_info_t.rxrate);
		DEBUG("send  %d",p->pair_keep_info_t.pair_live_send_num);
		DEBUG("get %d",p->pair_keep_info_t.pair_live_get_num);
		DEBUG("wlanconfig time  %d",p->time_newest);
		DEBUG("keep live time  %d",p->pair_keep_info_t.pair_live_get_time);
		DEBUG("version %d",p->version_flag);
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
