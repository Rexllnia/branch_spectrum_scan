#include "rg_wds.h"

void rg_wds_send_keep_data_fill_cpe(struct wds_keeplive_packet *keep_live_date_p) {
	memset(keep_live_date_p,0,sizeof(struct wds_keeplive_packet));
	keep_live_date_p->role = rg_ath_info_t.role;
	keep_live_date_p->lock = rg_gpio_info_t.gpio_lock_value;
	keep_live_date_p->unuse = 0xaa;
	keep_live_date_p->unuse2 = 0xaa;
	memcpy(keep_live_date_p->name,"abcd",strlen("abcd"));
	keep_live_date_p->sync_flag = SYNC_KEEP_LIVE;
}

void rg_wds_send_keep_date_cpe()
{
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}

	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_keeplive_packet keep_live_date;
	char buf[2000];

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&keep_live_date,0,sizeof(struct wds_keeplive_packet));

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_send_keep_data_fill_cpe(&keep_live_date);

	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&keep_live_date,sizeof(struct wds_keeplive_packet));
    /* 42代表：为KEEPALIVE报文多增加42字节，用于兼容旧版本多发42字节问题 */
	rg_send_raw_date(rg_ath_info_t.ath_wds_name, 42 + sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_keeplive_packet),buf,rg_pair_info_heap_t->mac);
}

const char *ether_sprintf(const unsigned char mac[6])
{
    static char buf[32];

    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

void rg_wds_get_keep_data_update(char *mac) {
	struct pair_dev_ath_info *p = rg_pair_info_heap_t;

	while (p) {
		if (memcmp(p->mac,mac,6) == 0) {
			struct sysinfo info;
			sysinfo(&info);
			p->pair_keep_info_t.pair_live_get_num++;
			p->pair_keep_info_t.pair_live_get_time = info.uptime;
			break;
		}
		p = p->next;
	}
}

//当时处理的时候把这些信息都用保活报文发送，所以导致了当前的各种问题，差评
void rg_wds_get_keep_date(char *data,int len) {
    if (rg_pair_info_heap_t == NULL ) {
        GPIO_DEBUG("now wlanconfig list is null");
        return;
    }

    if (len == sizeof(struct wds_keeplive_packet) || len == (sizeof(struct wds_keeplive_packet) + 1)) {
        //处理保活信息
        rg_wds_get_keep_data_update(data + 6);
    } else if(len >= (sizeof(struct wds_info_packet_head) + sizeof(struct wds_sn_mac_hostname))) {
        //AP端接受CPE发送过来的system info 信息，保存到链表
        rg_wds_get_system_info_ap(data);
        //CPE端接受AP发送过来的system info 信息，写入到TMP文件
        rg_wds_get_system_info_cpe(data);
        //处理保活信息
        rg_wds_get_keep_data_update(data + 6);
    }
}

void rg_wds_keep_date_send_ap(struct pair_dev_ath_info *p) {
	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}
	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_keeplive_packet keep_live_date;
	char buf[2000];

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&keep_live_date,0,sizeof(struct wds_keeplive_packet));

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_send_keep_data_fill_cpe(&keep_live_date);

	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&keep_live_date,sizeof(struct wds_keeplive_packet));
    /* 42代表：为KEEPALIVE报文多增加42字节，用于兼容旧版本多发42字节问题 */
	//printf("ap send to peer mac:%02x:%02x:%02x:%02x:%02x:%02x\n", p->mac[0], p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5]);
	rg_send_raw_date(rg_ath_info_t.ath_wds_name, 42 + sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_keeplive_packet),buf,p->mac);
}

void rg_wds_keep_data_respone() {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}

	struct pair_dev_ath_info *p = rg_pair_info_heap_t;

	while (p) {
		if (p->pair_keep_info_t.pair_live_get_num != p->pair_keep_info_t.pair_live_send_num) {
			p->pair_keep_info_t.pair_live_send_num = p->pair_keep_info_t.pair_live_get_num;
			rg_wds_keep_date_send_ap(p);
		}
		p = p->next;
	}
}
