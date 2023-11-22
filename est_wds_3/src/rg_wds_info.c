#include "rg_wds.h"

#define SYSTEM_INFO_FILE_1   "/tmp/wds_info.json"
#define SYSTEM_INFO_FILE_2   "/etc/config/wds_info.json"

#define SYSTEM_INFO_ROOL "ap"
#define SYSTEM_INFO_STA  "cpe"
//最大同步的设备的个数，隐含约定当前设备最多接入7台设备
#define SYSTEM_INFO_MAX_DEV_COUNT 8

void rg_wds_send_info_data_fill_all_cpe(struct wds_sn_mac_hostname *info_data_p) {
	memcpy(info_data_p->sn, rg_dev_info_t.sn, sizeof(info_data_p->sn) - 1);
	memcpy(info_data_p->hostname,rg_dev_info_t.host_name,sizeof(info_data_p->hostname) - 1);
	memcpy(info_data_p->system_mac,rg_dev_info_t.sys_mac,sizeof(info_data_p->system_mac));
	if (rg_gpio_info_t.gpio_lock_value == LOCK) {
		memcpy(info_data_p->lock_status,"LOCK",strlen("LOCK"));
	} else {
		memcpy(info_data_p->lock_status,"UNLOCK",strlen("UNLOCK"));
	}

	if (rg_pair_info_heap_t != NULL) {
		memset(info_data_p->wds_status,0,sizeof(info_data_p->wds_status));
		if (rg_wds_pair_offline(rg_pair_info_heap_t)) {
			//离线
			memcpy(info_data_p->wds_status,WDS_OFF,strlen(WDS_OFF));
		} else {
			//在线
			memcpy(info_data_p->wds_status,WDS_ON,strlen(WDS_ON));
		}
	}

	info_data_p->ip_address = rg_dev_info_t.ip;
}

void rg_wds_send_info_data_fill_all_ap(struct wds_sn_mac_hostname *info_data_p,struct pair_dev_ath_info *pair_p) {
	memcpy(info_data_p->ath_mac,pair_p->mac,6);
	memcpy(info_data_p->system_mac,pair_p->pair_dev_info_t.sys_mac,6);
	memcpy(info_data_p->sn,pair_p->pair_dev_info_t.sn,sizeof(pair_p->pair_dev_info_t.sn));
	memcpy(info_data_p->hostname,pair_p->pair_dev_info_t.host_name,sizeof(pair_p->pair_dev_info_t.host_name));
	if (pair_p->lock_info_t.gpio_lock_value == LOCK) {
		memcpy(info_data_p->lock_status,"LOCK",strlen("LOCK"));
	} else {
		memcpy(info_data_p->lock_status,"UNLOCK",strlen("UNLOCK"));
	}
	if (rg_wds_pair_offline(pair_p)) {
		//离线
		memcpy(info_data_p->wds_status,WDS_OFF,strlen(WDS_OFF));
	} else {
		//在线
		memcpy(info_data_p->wds_status,WDS_ON,strlen(WDS_ON));
	}

	//memcpy(info_data_p->wds_status,pair_p->mac,6);
	memcpy(info_data_p->role,SYSTEM_INFO_STA,strlen(SYSTEM_INFO_STA));
	info_data_p->ip_address = pair_p->pair_dev_info_t.ip;
	info_data_p->rssi= pair_p->pair_assioc_info_t.rssi;
	info_data_p->rate= pair_p->pair_assioc_info_t.rxrate;
}

void rg_wds_send_info_data_fill_self(struct wds_sn_mac_hostname *info_data_p) {
	memcpy(info_data_p->ath_mac,rg_ath_info_t.root_mac_hex,6);
	memcpy(info_data_p->system_mac,rg_dev_info_t.sys_mac,6);
	memcpy(info_data_p->sn,rg_dev_info_t.sn,sizeof(info_data_p->sn));
	memcpy(info_data_p->hostname,rg_dev_info_t.host_name,sizeof(info_data_p->hostname));
	if (rg_gpio_info_t.gpio_lock_value== LOCK) {
		memcpy(info_data_p->lock_status,"LOCK",strlen("LOCK"));
	} else {
		memcpy(info_data_p->lock_status,"UNLOCK",strlen("UNLOCK"));
	}

	//能收到就一定在线
	memcpy(info_data_p->wds_status,WDS_ON,strlen(WDS_ON));

	memcpy(info_data_p->role,SYSTEM_INFO_ROOL,strlen(SYSTEM_INFO_ROOL));
	info_data_p->ip_address = rg_dev_info_t.ip;
	info_data_p->rssi= 0;
	info_data_p->rate= 0;
}

void rg_wds_send_info_data_fill_head(struct wds_info_packet_head *info_head_p,char len) {
	memset(info_head_p,0,sizeof(struct wds_info_packet_head));
	info_head_p->role = rg_ath_info_t.role;
	info_head_p->lock = rg_gpio_info_t.gpio_lock_value;
	info_head_p->unuse = 0xaa;
	info_head_p->unuse2 = 0xaa;
	memcpy(info_head_p->name,"abcd",strlen("abcd"));
	info_head_p->sync_flag = SYNC_KEEP_LIVE;
	//CPE端一直是一个
	info_head_p->wds_len = len;
}

void rg_wds_send_cpe_info() {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}

	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_info_packet_head info_head_data;
	struct wds_sn_mac_hostname info_all_data;

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&info_head_data,0,sizeof(struct wds_info_packet_head));
	memset(&info_all_data,0,sizeof(struct wds_sn_mac_hostname));

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_send_info_data_fill_head(&info_head_data,1);
	rg_wds_send_info_data_fill_all_cpe(&info_all_data);

	char buf[2000];
	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&info_head_data,sizeof(struct wds_info_packet_head));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_info_packet_head),\
			&info_all_data,sizeof(struct wds_sn_mac_hostname));
    /* 42代表：为KEEPALIVE报文多增加42字节，用于兼容旧版本多发42字节问题 */
	rg_send_raw_date(rg_ath_info_t.ath_wds_name,\
		42 + sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_info_packet_head) + sizeof(struct wds_sn_mac_hostname) ,\
		buf,rg_pair_info_heap_t->mac);
}

void rg_wds_send_ap_info() {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}

	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_info_packet_head info_head_data;
	struct wds_sn_mac_hostname info_all_data;
	char len = 0;
	char buf[2000];

	pthread_mutex_lock(&rg_pair_mtx);
	struct pair_dev_ath_info *pair_p = rg_pair_info_heap_t;
	if (pair_p == NULL) {
		pthread_mutex_unlock(&rg_pair_mtx);
		return;
	}

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&info_head_data,0,sizeof(struct wds_info_packet_head));
	len = 1;//只发ap自身的信息就只有一个设备信息
	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_send_info_data_fill_head(&info_head_data,len);
	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&info_head_data,sizeof(struct wds_info_packet_head));


	//AP端发送本机的信息
	memset(&info_all_data,0,sizeof(struct wds_sn_mac_hostname));
	rg_wds_send_info_data_fill_self(&info_all_data);
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet) + \
			sizeof(struct wds_info_packet_head),\
			&info_all_data,sizeof(struct wds_sn_mac_hostname));

	while (pair_p) {
        /* 42代表：为KEEPALIVE报文多增加42字节，用于兼容旧版本多发42字节问题 */
		rg_send_raw_date(rg_ath_info_t.ath_wds_name,\
			42 + sizeof(struct mac_ip_udp_wds_packet) + \
			sizeof(struct wds_info_packet_head) + \
			len * sizeof(struct wds_sn_mac_hostname) ,\
			buf,pair_p->mac);
		pair_p = pair_p->next;
	}

	pthread_mutex_unlock(&rg_pair_mtx);
}

//AP端获取到system info信息之后，保存都链表
void rg_wds_get_system_info_ap(char *data) {
	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}

	//操作到链表，需要保护

	pthread_mutex_lock(&rg_pair_mtx);
	char *mac_cpe;
	struct pair_dev_ath_info *pair_p = rg_pair_info_heap_t;
	struct wds_sn_mac_hostname *system_info_p = (struct wds_sn_mac_hostname *)((char *)data + 44 + sizeof(struct wds_info_packet_head));
	mac_cpe = data + 6;

	while (pair_p) {
		if (memcmp(pair_p->mac,mac_cpe,6) == 0) {
			if (memcmp(pair_p->pair_dev_info_t.sys_mac,system_info_p->system_mac,6) != 0) {
				memcpy(pair_p->pair_dev_info_t.sys_mac,system_info_p->system_mac,6);
				dump_date(mac_cpe,6);
			}

			if (memcmp(pair_p->pair_dev_info_t.sn,system_info_p->sn,sizeof(system_info_p->sn)) != 0) {
				memset(pair_p->pair_dev_info_t.sn,0,sizeof(pair_p->pair_dev_info_t.sn));
				memcpy(pair_p->pair_dev_info_t.sn,system_info_p->sn,sizeof(pair_p->pair_dev_info_t.sn));
				GPIO_DEBUG("sn %s",pair_p->pair_dev_info_t.sn);
			}

			if (memcmp(pair_p->pair_dev_info_t.host_name,system_info_p->hostname,sizeof(pair_p->pair_dev_info_t.host_name)) != 0) {
				memset(pair_p->pair_dev_info_t.host_name,0,sizeof(pair_p->pair_dev_info_t.host_name));
				memcpy(pair_p->pair_dev_info_t.host_name,system_info_p->hostname,sizeof(pair_p->pair_dev_info_t.host_name));
				GPIO_DEBUG("host_name %s",pair_p->pair_dev_info_t.host_name);
			}

			if (memcmp(system_info_p->lock_status,"LOCK",strlen("LOCK")) == 0) {
				pair_p->lock_info_t.gpio_lock_value = LOCK;
			} else {
				pair_p->lock_info_t.gpio_lock_value = UNLOCK;
			}

			pair_p->pair_dev_info_t.ip = system_info_p->ip_address;

			break;
		}
		pair_p = pair_p->next;
	}

	pthread_mutex_unlock(&rg_pair_mtx);
}

//CPE端获取到信息之后，直接写入tmp文件
void rg_wds_get_system_info_cpe(char *data) {
	struct wds_sn_mac_hostname *wds_data_p = NULL;
	char buf[50];
	int i = 0;
	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}

	struct wds_info_packet_head *wds_head_p = (struct wds_info_packet_head *)((char *)data + 44);
	char len = wds_head_p->wds_len;
	GPIO_DEBUG("len=%d", len);
	if (0==len) {
		return;
	}

	while (i<len) { //为了兼容旧版本的ap(此版本ap可以发送自身以及所关联的所有cpe设备的信息，即多台设备信息)，新版本ap只发送ap自身信息，即单台设备信息。
		wds_data_p = (struct wds_sn_mac_hostname *)((char *)data + 44 + sizeof(struct wds_info_packet_head)+\
		i*sizeof(struct wds_sn_mac_hostname));

		memset(buf,0,sizeof(buf));
		sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",
			wds_data_p->system_mac[0],wds_data_p->system_mac[1],
			wds_data_p->system_mac[2],wds_data_p->system_mac[3],
			wds_data_p->system_mac[4],wds_data_p->system_mac[5]);
		GPIO_DEBUG("wds_data_p->role=%s sysmac=%s", wds_data_p->role, buf);
		if (strcmp(wds_data_p->role,"ap") == 0) {
		    rg_wds_misc_write_file("/tmp/.ap_sysmac",buf,strlen(buf));
			rg_wds_misc_write_file("/tmp/.ap_sn",wds_data_p->sn,strlen(wds_data_p->sn));
			break;
		}

		i++;
	}
}

void rg_wds_sysinfo_write_ap() {
	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}

	pthread_mutex_lock(&rg_pair_mtx);
	struct pair_dev_ath_info *pair_p = rg_pair_info_heap_t;
	char buf[50];
	struct in_addr in;
	json_object *file = json_object_new_object();
	json_object *section = json_object_new_array();

	while (pair_p) {
		json_object *item = json_object_new_object();

		json_object_object_add(item, "SN", json_object_new_string(pair_p->pair_dev_info_t.sn));
		GPIO_DEBUG("AP write pair_p->pair_dev_info_t.sn:%s", pair_p->pair_dev_info_t.sn);

		memset(buf,0,sizeof(buf));
		sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
			pair_p->pair_dev_info_t.sys_mac[0],pair_p->pair_dev_info_t.sys_mac[1],\
			pair_p->pair_dev_info_t.sys_mac[2],pair_p->pair_dev_info_t.sys_mac[3],\
			pair_p->pair_dev_info_t.sys_mac[4],pair_p->pair_dev_info_t.sys_mac[5]);
		json_object_object_add(item, "MAC", json_object_new_string(buf));

		memset(buf,0,sizeof(buf));
		sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",\
			pair_p->mac[0],pair_p->mac[1],pair_p->mac[2],
			pair_p->mac[3],pair_p->mac[4],pair_p->mac[5]);
		json_object_object_add(item, "ATHMAC", json_object_new_string(buf));

		json_object_object_add(item, "HOSTNAME", json_object_new_string(pair_p->pair_dev_info_t.host_name));
        json_object_object_add(item, "SOFTVERSION", json_object_new_string(pair_p->pair_dev_info_t.software_version));
		json_object_object_add(item, "ROLE", json_object_new_string(SYSTEM_INFO_STA));

		if (rg_wds_pair_offline(pair_p)) {
			json_object_object_add(item, "STATUS", json_object_new_string(WDS_OFF));
		} else {
			json_object_object_add(item, "STATUS", json_object_new_string(WDS_ON));
		}
		if (pair_p->lock_info_t.gpio_lock_value == LOCK) {
			json_object_object_add(item, "LOCK", json_object_new_string("LOCK"));
		} else {
			json_object_object_add(item, "LOCK", json_object_new_string("UNLOCK"));

		}

		in.s_addr = pair_p->pair_dev_info_t.ip;
		json_object_object_add(item, "IP_ADDRESS", json_object_new_string(inet_ntoa(in)));

		memset(buf,0,sizeof(buf));
		sprintf(buf,"%d",pair_p->pair_assioc_info_t.rxrate);
		json_object_object_add(item, "RATE", json_object_new_string(buf));

		memset(buf,0,sizeof(buf));
		sprintf(buf,"%d",pair_p->pair_assioc_info_t.rssi);
		json_object_object_add(item, "RSSI", json_object_new_string(buf));

		json_object_array_add(section, item);
		pair_p = pair_p->next;
	}

	pthread_mutex_unlock(&rg_pair_mtx);
	rg_wds_misc_clear_file(SYSTEM_INFO_FILE_1);
	json_object_object_add(file, "LIST", section);
	const char *str = json_object_to_json_string(file);

	int fd;
	fd = open(SYSTEM_INFO_FILE_1, O_CREAT | O_RDWR,0644);
	write(fd,str,strlen(str));
	close(fd);

	json_object_put(file);
}


void rg_wds_sysinfo_update_cpe() {
	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}

	//当对端设备都消失则清空文件
	if (rg_pair_info_heap_t == NULL) {
		rg_wds_misc_clear_file(SYSTEM_INFO_FILE_1);
	}
}

