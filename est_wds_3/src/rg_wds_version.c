#include "rg_wds.h"

char rg_wds_version_cpe_check() {
	struct pair_dev_ath_info *p = rg_pair_info_heap_t;
	char flag = 0;

	while (p) {
		if (p->version_flag == 0) {
			flag++;
			break;
		}
		p = p->next;
	}
	return flag;
}

char rg_wds_version_cpe_set(char *data) {
	struct pair_dev_ath_info *p = rg_pair_info_heap_t;
	char flag = 0;
	char *mac = data + 6;
	struct wds_date_head *version_data = (struct wds_date_head *)((char *)data + 44);
#ifdef OPEN_VER_CPE
	GPIO_DEBUG("mac:%s,", mac);unsigned char role;	 //0,表示cpe，1表示ap
	GPIO_DEBUG("version_date->role:%d", version_data->role); //0/1
	GPIO_DEBUG("version_date->bssid:%s", version_data->bssid);
	GPIO_DEBUG("version_date->lock:%d", version_data->lock); //rg_gpio_infot.gpio_lock_value
	GPIO_DEBUG("version_date->sync_flag:%d", version_data->sync_flag);//10
	GPIO_DEBUG("version_date->cpe_num:%d", version_data->cpe_num);
	GPIO_DEBUG("version_date->unuse:%d", version_data->unuse);//旧版本数量
	GPIO_DEBUG("version_date->unuse2:%d", version_data->unuse2);
	GPIO_DEBUG("version_date->name:%s", version_data->name);//abcd
#endif
	while (p) {
		if (memcmp(p->mac,mac,6) == 0) {
			p->version_flag = 1;
			break;
		}
		p = p->next;
	}
	return flag;
}

void rg_wds_version_send_data_fill(struct wds_date_head *version_date_p,char flag) {
	memset(version_date_p,0,sizeof(struct wds_date_head));
	version_date_p->role = rg_ath_info_t.role;
	version_date_p->lock = rg_gpio_info_t.gpio_lock_value;
	version_date_p->unuse = flag;
	version_date_p->unuse2 = 0xaa;
	memcpy(version_date_p->name,"abcd",strlen("abcd"));
	version_date_p->sync_flag = SYNC_VERSION;
}

void rg_wds_version_send_ap_all(struct pair_dev_ath_info *p,char flag) {
	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_date_head version_data;
	char buf[2000];
	char i;

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&version_data,0,sizeof(struct wds_date_head));

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_version_send_data_fill(&version_data,flag);

	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&version_data,sizeof(struct wds_date_head));
	for (i = 0;i < 5;i++){
		rg_send_raw_date(rg_ath_info_t.ath_wds_name,sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head),buf,p->mac);
	}
}

void rg_wds_version_send_ap() {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}

	struct pair_dev_ath_info *p = rg_pair_info_heap_t;
	char flag = 0;

	flag = rg_wds_version_cpe_check();

	while (p) {
		rg_wds_version_send_ap_all(p,flag);
		p = p->next;
	}
}

void rg_wds_version_send_cpe() {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}

	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_date_head version_data;
	char buf[2000];
	char flag = 0;
	char i = 0;

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&version_data,0,sizeof(struct wds_date_head));

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_version_send_data_fill(&version_data,flag);

	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&version_data,sizeof(struct wds_date_head));
	for (i = 0;i < 5;i++) {
		rg_send_raw_date(rg_ath_info_t.ath_wds_name,sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head),buf,rg_pair_info_heap_t->mac);
	}
}

void  rg_wds_version_get_ap(char *data,int len) {
	char *mac = data + 6;

	pthread_mutex_lock(&rg_pair_mtx);
	rg_wds_version_cpe_set(data);
	pthread_mutex_unlock(&rg_pair_mtx);
}

void  rg_wds_version_get_cpe(char *data,int len) {
	struct wds_date_head *version_data;

	version_data = (struct wds_date_head *)((char *)data + 44);

    pthread_mutex_lock(&rg_pair_mtx);
    /* 校验桥接关联条件，来判断置上version_flag */
    if (rg_cpe_check_setssid_condition(data) == -1) {
        pthread_mutex_unlock(&rg_pair_mtx);
        return;
    }

	//1表示AP端网络中包含有旧版本设备
	if (version_data->unuse == 1) {
		rg_pair_info_heap_t->version_flag = 0;
	} else if (version_data->unuse == 0) {
		rg_pair_info_heap_t->version_flag = 1;
	} else {
		rg_pair_info_heap_t->version_flag = 0;
	}
	pthread_mutex_unlock(&rg_pair_mtx);
}

void rg_wds_version_get(char *data,int len) {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		rg_wds_version_get_ap(data,len);
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		rg_wds_version_get_cpe(data,len);
	}
}

// CPE端发送 软件版本号信息
void rg_wds_soft_version_cpe_send() {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}

  	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_date_head soft_version_date;
	char buf[2000];
    char *tmp;
    char i;
    int data_len = 0;
    char mac[6];

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&soft_version_date,0,sizeof(struct wds_date_head));

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_fill_head(&soft_version_date,SYNC_SOFTWARE_VERSION,1);

    tmp = buf;
	memset(tmp,0,sizeof(tmp));

	memcpy(tmp,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
    tmp = tmp + sizeof(struct mac_ip_udp_wds_packet);
	memcpy(tmp,&soft_version_date,sizeof(struct wds_date_head));
    tmp = tmp + sizeof(struct wds_date_head);
    memcpy(tmp,rg_dev_info_t.software_version,sizeof(rg_dev_info_t.software_version));

    pthread_mutex_lock(&rg_pair_mtx);
    if (rg_pair_info_heap_t->mac != NULL) {
        memcpy(mac,rg_pair_info_heap_t->mac,6);
    } else {
        pthread_mutex_unlock(&rg_pair_mtx);
        return;
    }
    pthread_mutex_unlock(&rg_pair_mtx);

    data_len = sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head) + sizeof(rg_dev_info_t.software_version);
	for (i = 0;i < 5;i++) {
		rg_send_raw_date(rg_ath_info_t.ath_wds_name,data_len,buf,mac);
	}
}

// AP端发送 软件版本号信息
void rg_wds_soft_version_ap_send() {
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}

  	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_date_head soft_version_date;
	char buf[2000];
    char *tmp;
    char i;
    int data_len = 0;
    char cpe_len;
    char mac[6];
    struct pair_dev_ath_info *p = rg_pair_info_heap_t;

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&soft_version_date,0,sizeof(struct wds_date_head));

    pthread_mutex_lock(&rg_pair_mtx);
	rg_wds_send_date_head_init(&eth_heap_p);

    cpe_len = rg_wds_pair_list_len();

	rg_wds_fill_head(&soft_version_date,SYNC_SOFTWARE_VERSION,1 + cpe_len);

    memset(buf,0,sizeof(buf));
    tmp = buf;

	memcpy(tmp,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
    tmp = tmp + sizeof(struct mac_ip_udp_wds_packet);
	memcpy(tmp,&soft_version_date,sizeof(struct wds_date_head));
    tmp = tmp + sizeof(struct wds_date_head);
    memcpy(tmp,rg_ath_info_t.root_mac_hex,6);
    tmp = tmp + 6;
    memcpy(tmp,rg_dev_info_t.software_version,sizeof(rg_dev_info_t.software_version));
    tmp = tmp + sizeof(rg_dev_info_t.software_version);

    while (p) {
        memcpy(tmp,p->mac,6);
        tmp = tmp + 6;
        memcpy(tmp,p->pair_dev_info_t.software_version,sizeof(rg_dev_info_t.software_version));
        tmp = tmp + sizeof(rg_dev_info_t.software_version);
        p = p->next;
    }

    data_len = sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head) + (cpe_len + 1)*sizeof(struct wds_softversion_packet);

    p = rg_pair_info_heap_t;
    while (p) {
        for (i = 0;i < 5;i++) {
            rg_send_raw_date(rg_ath_info_t.ath_wds_name,data_len,buf,p->mac);
        }

        p = p->next;
    }

    pthread_mutex_unlock(&rg_pair_mtx);
}

// AP端获取到软件版本号信息
void rg_wds_get_softversion_ap(unsigned char *packet,int len) {
    pthread_mutex_lock(&rg_pair_mtx);
    struct pair_dev_ath_info *p = rg_pair_info_heap_t;
    char *mac = packet + 6;
    char *softversion_date = ((char *)packet + 44 + sizeof(struct wds_date_head));

    while (p) {
        if (memcmp(mac,p->mac,6) == 0) {
            if (memcmp(p->pair_dev_info_t.software_version,softversion_date,sizeof(p->pair_dev_info_t.software_version)) != 0) {
                memcpy(p->pair_dev_info_t.software_version,softversion_date,sizeof(p->pair_dev_info_t.software_version));
                GPIO_DEBUG("software_version %s",p->pair_dev_info_t.software_version);
                break;
            }
        }
        p = p->next;
    }

    pthread_mutex_unlock(&rg_pair_mtx);
}

// CPE端获取到软件版本号信息
void rg_wds_get_softversion_cpe(unsigned char *data,int data_len) {
    char *mac = data + 6;
    char len;
    char i = 0;
    struct wds_softversion_packet *softversion_date = ((char *)data + 44 + sizeof(struct wds_date_head));
    struct wds_date_head *version_data = (struct wds_date_head *)((char *)data + 44);
    char buf[20];
    len = version_data->cpe_num;

    json_object *file = json_object_new_object();
    json_object *section = json_object_new_array();

	while (i < len) {
        softversion_date = softversion_date + i;
		if (memcmp(softversion_date->mac,rg_ath_info_t.root_mac_hex,6) == 0) {
            goto loop;
		}

		json_object *item = json_object_new_object();
 		memset(buf,0,sizeof(buf));
		sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",
			softversion_date->mac[0],softversion_date->mac[1],softversion_date->mac[2],
			softversion_date->mac[3],softversion_date->mac[4],softversion_date->mac[5]);
		json_object_object_add(item, "ATHMAC", json_object_new_string(buf));

		json_object_object_add(item, "SOFTVERSION", json_object_new_string(softversion_date->softverson));

		json_object_array_add(section, item);
loop:
		i++;
	}
    pthread_mutex_lock(&mtx_wds_softversion_file);
	rg_wds_misc_clear_file(SOFT_VERSION_FILE);

	json_object_object_add(file, "LIST", section);
	const char *str = json_object_to_json_string(file);

	int fd;
	fd = open(SOFT_VERSION_FILE, O_CREAT | O_RDWR,0644);
	write(fd,str,strlen(str));
	close(fd);
    pthread_mutex_unlock(&mtx_wds_softversion_file);
    json_object_put(file);
}

void rg_wds_get_softversion(unsigned char *packet,int len) {
    if (rg_ath_info_t.role == MODE_AP) {
        rg_wds_get_softversion_ap(packet,len);
    }

    if (rg_ath_info_t.role == MODE_CPE) {
        rg_wds_get_softversion_cpe(packet,len);
    }
}
