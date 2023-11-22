#include "rg_wds.h"

#define BEACON_CHECK_TMIE     30*60   //30����֮�󣬿ͻ�û��ͨ��lock���������豸�����Զ�ѡ��һ����ǰ�ź���ǰ��
#define BEACON_MIN_JOIN_RSSI  20
#define BEACON_RESULT_FILE  "/tmp/wds_scanner_list.json"

int nl_fd;
struct sockaddr_nl nl_address;
int nl_family_id;
struct nlattr *nl_na;
struct { //
    struct nlmsghdr n;
    struct genlmsghdr g;
    char buf[256];
} nl_request_msg, nl_response_msg;

void rg_wds_beacon_show() {
	struct wds_ssid_netid_t *p;
	p = wds_ssid_list_p;
	int i = 0;

	DEBUG("--------------------------------   begin  -----------------------------------");
	while (p != NULL) {
		DEBUG("i %d",i);
		DEBUG("role_ap %d",p->role_ap);
		DEBUG("role_cpe %d",p->role_cpe);
		DEBUG("rssi_ap %d",p->rssi_ap);
		DEBUG("rssi_cpe %d",p->rssi_cpe);
		DEBUG("time_update_ap %d",p->time_update_ap);
		DEBUG("time_update_cpe %d",p->time_update_cpe);
		DEBUG("wds_connect_status_cpe %d",p->wds_connect_status_cpe);
		DEBUG("cpe rssi_max_count %d",p->rssi_max_count);
		DEBUG("wds_ssid %s",p->wds_ssid);
		dump_date(p->mac,sizeof(p->mac));
		p = p->next;
		i++;
	}
	DEBUG("---------------------------    end   ----------------------------------------");
}

char wds_list_length() {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	char len = 0;

	while (p != NULL) {
		len++;
		p = p->next;
	}

	return len;
}


//�����Ѿ����ڵĽڵ����Ϣ,���²�������
void wds_list_update(struct wds_beacon_info_s *beacon_p,struct wds_ssid_netid_t *wds_list_p) {
	struct sysinfo info;

	//��ȡ��ǰʱ��
	sysinfo(&info);

	if (beacon_p->role == ROLE_AP) {
		//���ܵ�AP���ź�ǿ�ȣ��Ե�ǰ��Ϊ׼
		//wds_list_p->rssi_ap = beacon_p->rssi;
        //��С�źŲ���
        if (beacon_p->rssi > wds_list_p->rssi_ap) {
            wds_list_p->rssi_ap = beacon_p->rssi;
        } else {
            if (wds_list_p->rssi_ap > 0) {
                wds_list_p->rssi_ap--;
            }
        }

		wds_list_p->role_ap = 1;
		wds_list_p->time_update_ap = info.uptime;
        /* ap sn��Ϣ�洢 */
        memset(wds_list_p->ap_sn, 0, sizeof(wds_list_p->ap_sn));
        strncpy(wds_list_p->ap_sn, beacon_p->sn, sizeof(wds_list_p->ap_sn) - 1);
	} else if (beacon_p->role == ROLE_CPE) {
		//���ܵ�CPE���ź�ǿ�ȣ��Ե�ǰ�ĵر���ǿս��Ϊ׼����Ϊ�п��ܴ��ڶ��CPE�����������ֻ������ǿ��Ϊ׼
		wds_list_p->role_cpe= 1;
		//�ź�ǿ�������Ϊ�޶�
		if (beacon_p->rssi >= wds_list_p->rssi_cpe) {
			wds_list_p->rssi_cpe = beacon_p->rssi;
			memcpy(wds_list_p->mac,beacon_p->mac,sizeof(wds_list_p->mac));
			wds_list_p->time_update_cpe = info.uptime;
			wds_list_p->wds_connect_status_cpe = beacon_p->wds_connect_status;
		} else {
            //ÿ�μ�С1���ȴ���ߵ��Ǹ��ź����¸��£��������Ա���rssi���������µ�
			wds_list_p->time_update_cpe = info.uptime;
			wds_list_p->wds_connect_status_cpe = beacon_p->wds_connect_status;
            if (wds_list_p->rssi_cpe > 0) {
                wds_list_p->rssi_cpe--;
            }
		}
        /* cpe sn��Ϣ�洢 */
        memset(wds_list_p->cpe_sn, 0, sizeof(wds_list_p->cpe_sn));
        strncpy(wds_list_p->cpe_sn, beacon_p->sn, sizeof(wds_list_p->cpe_sn) - 1);
	}
}

//�����Ѿ����ڵĽڵ����Ϣ	��ȫ������
void wds_list_update_all(struct wds_beacon_info_s *beacon_p,struct wds_ssid_netid_t *wds_list_p) {
	struct sysinfo info;

	//��ȡ��ǰʱ��
	sysinfo(&info);

	//SSID����
	memcpy(wds_list_p->wds_ssid,beacon_p->wds_ssid,sizeof(wds_list_p->wds_ssid));
	if (beacon_p->role == ROLE_AP) {
		//���ܵ�AP���ź�ǿ�ȣ��Ե�ǰ��Ϊ׼
		wds_list_p->rssi_ap = beacon_p->rssi;
		wds_list_p->role_ap = 1;
		wds_list_p->time_update_ap = info.uptime;
        /* ap sn��Ϣ�洢 */
        memset(wds_list_p->ap_sn, 0, sizeof(wds_list_p->ap_sn));
        strncpy(wds_list_p->ap_sn, beacon_p->sn, sizeof(wds_list_p->ap_sn) - 1);
	} else if (beacon_p->role == ROLE_CPE) {
		//���ܵ�CPE���ź�ǿ�ȣ��Ե�ǰ�ĵر���ǿս��Ϊ׼����Ϊ�п��ܴ��ڶ��CPE�����������ֻ������ǿ��Ϊ׼
        wds_list_p->role_cpe = 1;
		wds_list_p->rssi_cpe = beacon_p->rssi;
		wds_list_p->time_update_cpe = info.uptime;
		memcpy(wds_list_p->mac,beacon_p->mac,sizeof(beacon_p->mac));
		wds_list_p->wds_connect_status_cpe = beacon_p->wds_connect_status;
        /* cpe sn��Ϣ�洢 */
        memset(wds_list_p->cpe_sn, 0, sizeof(wds_list_p->cpe_sn));
        strncpy(wds_list_p->cpe_sn, beacon_p->sn, sizeof(wds_list_p->cpe_sn) - 1);
	}
}

//�ҳ�RSSI��С�Ľڵ�
struct wds_ssid_netid_t * wds_list_find_min_rssi() {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	struct wds_ssid_netid_t *p_dst;
	char len = 0;

	int rssi = 10000;
	int rssi_tmp = 0;

	while (p != NULL) {
		//�ȶԵ�ʱ��Ҫ�ȵ�ǰCPE��AP�Ķ�Ҫ��
		if (p->rssi_ap >= p->rssi_cpe) {
			rssi_tmp = p->rssi_ap;
		} else {
			rssi_tmp = p->rssi_cpe;
		}

		if (rssi_tmp < rssi) {
			rssi = rssi_tmp;
			p_dst = p;
		}
		len++;
		p = p->next;
	}

	return p_dst;
}

char wds_list_rssi_compare(struct wds_ssid_netid_t *p,int rssi) {
	int rssi_tmp = 0;
	char ret = 0;

	if (p->rssi_ap >= p->rssi_cpe) {
		rssi_tmp = p->rssi_ap;
	} else {
		rssi_tmp = p->rssi_cpe;
	}

	if (rssi >= rssi_tmp) {
		if (rssi - rssi_tmp >= WDS_LIST_RSSI_COMPARE) {
			ret = 1;
		}
	}

	return ret;
}

//�ҳ�RSSI���Ľڵ�
struct wds_ssid_netid_t * wds_list_find_max_rssi(char role) {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	struct wds_ssid_netid_t *p_dst = NULL;

	int rssi = 0;
	int rssi_tmp = 0;

	while (p != NULL) {
		if (p->role_ap == 1 && role == MODE_CPE) {
			//�ҵ���ǰ��AP���ڵ�����ķ�Ĭ��SSID������
			//�ȶԵ�ʱ��Ҫ�ȵ�ǰCPE��AP�Ķ�Ҫ��
			if (p->rssi_ap >= p->rssi_cpe) {
				rssi_tmp = p->rssi_ap;
			} else {
				rssi_tmp = p->rssi_cpe;
			}

			//DEBUG("rssi_tmp %d rssi %d",rssi_tmp,rssi);
			if (rssi_tmp > rssi) {
				rssi = rssi_tmp;
				p_dst = p;
			}
		} else if (p->role_ap == 0 && p->role_cpe == 1 && role == MODE_AP) {
			//AP��������磬һ���ǲ����Ѿ���AP���ڵģ����ٵ�ǰ���ܿ���AP�Ĵ��ڣ����ֻ���µ��ˣ��������û�а취��������
			//�ȶԵ�ʱ��Ҫ�ȵ�ǰCPE��AP�Ķ�Ҫ��
			if (p->rssi_ap >= p->rssi_cpe) {
				rssi_tmp = p->rssi_ap;
			} else {
				rssi_tmp = p->rssi_cpe;
			}

			//DEBUG("rssi_tmp %d rssi %d",rssi_tmp,rssi);
			if (rssi_tmp > rssi) {
				rssi = rssi_tmp;
				p_dst = p;
			}
		}
		p = p->next;
	}

	return p_dst;
}

//��ӽڵ����Ϣ
void wds_list_add(struct wds_beacon_info_s *beacon_p,struct wds_ssid_netid_t *wds_list_p) {
	char len;
	struct wds_ssid_netid_t *p;
	int rssi = 0;

	len = wds_list_length();

	//����С��10����ʱ��ֱ����ӾͿ��ԣ������Ļ����ͱȶ��������Ǹ������С�Ļ�����ֱ��ɾ����Ȼ����ɾ��
	if (len < WDS_LIST_MAX_LENGTH) {
		p = (struct wds_ssid_netid_t *)malloc(sizeof(struct wds_ssid_netid_t));
		if (p == NULL) {
			DEBUG("malloc error");
			return;
		}
        memset(p,0,sizeof(struct wds_ssid_netid_t));
		wds_list_update_all(beacon_p,p);
		if (wds_list_p == NULL) {
			wds_ssid_list_p = p;
		} else {
			wds_list_p->next = p;
		}
	} else {
		p = wds_list_find_min_rssi();
		if (p->rssi_ap >= p->rssi_cpe) {
			rssi = p->rssi_ap;
		} else {
			rssi = p->rssi_cpe;
		}

		//DEBUG("rssi %d beacon_p->rssi %d",rssi,beacon_p->rssi);
		//�ź��в�࣬������һ���ķ�Χ�ڣ����Ը��¸ýڵ�
		if (beacon_p->rssi - rssi >= RSSI_DELETE) {
			wds_list_update_all(beacon_p,p);
			DEBUG("rssi %d beacon_p->rssi %d",rssi,beacon_p->rssi);
		}
	}
}

void wds_list_clear(struct wds_ssid_netid_t *p) {
	p->rssi_ap = 0;
	p->rssi_cpe = 0;
	p->role_ap = 0;
	p->role_cpe = 0;
	p->rssi_max_count = 0;
	p->time_update_ap = 0;
	p->time_update_cpe = 0;
	p->wds_connect_status_cpe = 0;
	memset(p->wds_ssid,0,sizeof(p->wds_ssid));
	memset(p->mac,0,sizeof(p->mac));
    memset(p->ap_sn, 0, sizeof(p->ap_sn));
    memset(p->cpe_sn, 0, sizeof(p->cpe_sn));
}
void wds_list_time_update() {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	struct sysinfo info;
	char len = 0;

	//��ȡ��ǰʱ��
	sysinfo(&info);

	//��������Ϊ0����ɾ�������ܻᱻ�滻
	while (p != NULL) {
		if ((p->time_update_ap > 0 || p->time_update_cpe > 0) && info.uptime - p->time_update_ap >= WDS_LIST_UPTIME && info.uptime - p->time_update_cpe >= WDS_LIST_UPTIME) {
			DEBUG("len %d info.uptime %d p->time_update_ap",len,info.uptime,p->time_update_ap);
			wds_list_clear(p);
		}
		len++;
		p = p->next;
	}
}

char rg_wds_list_scanner() {

	pthread_mutex_lock(&mtx_wds_beacon_list);
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	char buf[20];

	json_object *file = json_object_new_object();
	json_object *section = json_object_new_array();

	while (p != NULL) {
		if (strlen(p->wds_ssid) != 0) {
            //APֱ�ӹ��� ��AP��wds
//            if (rg_ath_info_t.role == MODE_AP) {
//                if (p->role_ap == 1) {
//                    goto loop;
//                }
//            }
			json_object *item = json_object_new_object();
			json_object_object_add(item, "ssid", json_object_new_string(p->wds_ssid));

			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->role_ap);
			json_object_object_add(item, "ap", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
            if (p->rssi_ap > 0) {
                sprintf(buf,"%d",p->rssi_ap - 95);
            }
			json_object_object_add(item, "ap_rssi", json_object_new_string(buf));

			memset(buf, 0, sizeof(buf));
            if (strlen(p->ap_sn)) {
                sprintf(buf, "%s", p->ap_sn);
            }
            json_object_object_add(item, "ap_peer_sn", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->role_cpe);
			json_object_object_add(item, "cpe", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
            if (p->rssi_cpe > 0) {
                sprintf(buf,"%d",p->rssi_cpe - 95);
            }
			json_object_object_add(item, "cpe_rssi", json_object_new_string(buf));

			memset(buf, 0, sizeof(buf));
            if (strlen(p->cpe_sn)) {
                sprintf(buf, "%s", p->cpe_sn);
            }
            json_object_object_add(item, "cpe_peer_sn", json_object_new_string(buf));

			json_object_array_add(section, item);
		}
loop:
		p = p->next;
	}
	pthread_mutex_unlock(&mtx_wds_beacon_list);
	json_object_object_add(file, "LIST", section);

	const char *str = json_object_to_json_string(file);

	int fd;
	/* ��һ���ļ� */
	fd = open(BEACON_RESULT_FILE,O_RDWR);
	if(fd < 0)
	{
		printf("open file.txt failed\n");
	}
	else
	{
		/* ����ļ� */
		ftruncate(fd,0);
		/* ���������ļ�ƫ���� */
		lseek(fd,0,SEEK_SET);
		close(fd);
	}

	fd = open(BEACON_RESULT_FILE, O_CREAT | O_RDWR,0644);
	write(fd,str,strlen(str));
	close(fd);
	json_object_put(file);
}

void rg_wds_beacon_process(struct wds_beacon_info_s *beacon_p) {
	struct wds_ssid_netid_t *p;
	struct wds_ssid_netid_t *p_last;
	char len = 0;

	if (strlen(beacon_p->wds_ssid) == 0 || beacon_p->rssi == 0 || (beacon_p->role != ROLE_AP && beacon_p->role != ROLE_CPE)) {
		DEBUG("beacon error");
		return;
	}

	len = wds_list_length();

	p = wds_ssid_list_p;
	p_last = p;
	while (p != NULL) {
		//�ҵ��������ID
		if (memcmp(p->wds_ssid,beacon_p->wds_ssid,sizeof(p->wds_ssid)) == 0) {
			//DEBUG("beacon_p->wds_ssid %s",beacon_p->wds_ssid);
			wds_list_update(beacon_p,p);
			break;
		}
		p_last = p;
		p = p->next;
	}

	if (p == NULL && wds_ssid_list_p == NULL) {
		//һ����û���ҵ�,��һ����û��
		wds_list_add(beacon_p,wds_ssid_list_p);
	} else if(p == NULL) {
		//����һ����ֵ
		wds_list_add(beacon_p,p_last);
	}
}

int rg_wds_beacon_pthread(void) {
    char ntv_sn[14];
	struct wds_beacon_info_s *wds_beacon_info;
	int len = 0;

    memset(ntv_sn, 0, sizeof(ntv_sn));
    rg_wds_misc_get_uci_option(WDS_GETSN_CMD, ntv_sn, sizeof(ntv_sn));

begin:
	while (1) {
	    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	    if (nl_fd < 0) {
	        perror("socket()");
			sleep(5);
	        continue;
	    }

	    memset(&nl_address, 0, sizeof(nl_address));
	    nl_address.nl_family = AF_NETLINK;
	    nl_address.nl_groups = 0;

	    if (bind(nl_fd, (struct sockaddr *) &nl_address, sizeof(nl_address)) < 0) {
	        perror("bind()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    nl_request_msg.n.nlmsg_type = GENL_ID_CTRL;//�����ں���genl_ctl��id
	    nl_request_msg.n.nlmsg_flags = NLM_F_REQUEST;
	    nl_request_msg.n.nlmsg_seq = 0;
	    nl_request_msg.n.nlmsg_pid = getpid();
	    nl_request_msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	    //Populate the payload's "family header" : which in our case is genlmsghdr
	    nl_request_msg.g.cmd = CTRL_CMD_GETFAMILY;
	    nl_request_msg.g.version = 0x1;
	    //Populate the payload's "netlink attributes"
	    nl_na = (struct nlattr *) GENLMSG_DATA(&nl_request_msg);//��ʵ���൱����nl_request_msg ��buf���й���һ��nla

	    nl_na->nla_type = CTRL_ATTR_FAMILY_NAME;
	    nl_na->nla_len = strlen("CONTROL_EXMPL") + 1 + NLA_HDRLEN;
	    strcpy(NLA_DATA(nl_na), "CONTROL_EXMPL"); //Family name length can be upto 16 chars including \0

	    nl_request_msg.n.nlmsg_len += NLMSG_ALIGN(nl_na->nla_len);

	    memset(&nl_address, 0, sizeof(nl_address));
	    nl_address.nl_family = AF_NETLINK;

	    len= sendto(nl_fd, (char *) &nl_request_msg, nl_request_msg.n.nlmsg_len,
	               0, (struct sockaddr *) &nl_address, sizeof(nl_address));
	    if (len != nl_request_msg.n.nlmsg_len) {
	        perror("sendto()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    len= recv(nl_fd, &nl_response_msg, sizeof(nl_response_msg), 0);
	    if (len < 0) {
	        perror("recv()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    if (!NLMSG_OK((&nl_response_msg.n), len)) {
	        fprintf(stderr, "family ID request : invalid message\n");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    if (nl_response_msg.n.nlmsg_type == NLMSG_ERROR) { //error
	        fprintf(stderr, "family ID request : receive error\n");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    //������attribute�е�family id
	    nl_na = (struct nlattr *) GENLMSG_DATA(&nl_response_msg);
	    nl_na = (struct nlattr *) ((char *) nl_na + NLA_ALIGN(nl_na->nla_len));
	    if (nl_na->nla_type == CTRL_ATTR_FAMILY_ID) {
	        nl_family_id = *(__u16 *) NLA_DATA(nl_na);//��һ��ͨ�ž���Ϊ�˵õ���Ҫ��family ID
	    }

	    memset(&nl_request_msg, 0, sizeof(nl_request_msg));
	    memset(&nl_response_msg, 0, sizeof(nl_response_msg));

	    nl_request_msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	    nl_request_msg.n.nlmsg_type = nl_family_id;
	    nl_request_msg.n.nlmsg_flags = NLM_F_REQUEST;
	    nl_request_msg.n.nlmsg_seq = 60;
	    nl_request_msg.n.nlmsg_pid = getpid();
	    nl_request_msg.g.cmd = 1; //corresponds to DOC_EXMPL_C_ECHO;

	    nl_na = (struct nlattr *) GENLMSG_DATA(&nl_request_msg);
	    nl_na->nla_type = 1; // corresponds to DOC_EXMPL_A_MSG

	    nl_na->nla_len = sizeof(ntv_sn)+NLA_HDRLEN; //Message length
	    memcpy(NLA_DATA(nl_na), ntv_sn, sizeof(ntv_sn));

	    nl_request_msg.n.nlmsg_len += NLMSG_ALIGN(nl_na->nla_len);

	    memset(&nl_address, 0, sizeof(nl_address));
	    nl_address.nl_family = AF_NETLINK;

	    len = sendto(nl_fd, (char *) &nl_request_msg, nl_request_msg.n.nlmsg_len,
	            0, (struct sockaddr *) &nl_address, sizeof(nl_address));
	    if (len != nl_request_msg.n.nlmsg_len) {
	        perror("sendto()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }
	    printf("Sent to kernel: %s\n",MESSAGE_TO_KERNEL);
		break;
	}

    while (1) {
       memset(&nl_response_msg, 0, sizeof(nl_response_msg));
	   len = recv(nl_fd, &nl_response_msg, sizeof(nl_response_msg), 0);
	   if (len < 0) {
	       perror("recv()");
           close(nl_fd);
           sleep(3);
           goto begin;
	   }

	    //�쳣����
	   if (nl_response_msg.n.nlmsg_type == NLMSG_ERROR) { //Error
	   printf("Error while receiving reply from kernel: NACK Received\n");
	       close(nl_fd);
           sleep(3);
           goto begin;
	   }
	   if (len < 0) {
	       printf("Error while receiving reply from kernel\n");
	       close(nl_fd);
           sleep(3);
           goto begin;
	   }
	   if (!NLMSG_OK((&nl_response_msg.n), len)) {
	       printf("Error while receiving reply from kernel: Invalid Message\n");
	       close(nl_fd);
           sleep(3);
           goto begin;
	   }

	   //�����յ��������ں˵�reply
	   len = GENLMSG_PAYLOAD(&nl_response_msg.n);
	   nl_na = (struct nlattr *) GENLMSG_DATA(&nl_response_msg);
	   wds_beacon_info = (struct wds_beacon_info_s *)NLA_DATA(nl_na);

	   pthread_mutex_lock(&mtx_wds_beacon_list);
	   rg_wds_beacon_process(wds_beacon_info);
	   pthread_mutex_unlock(&mtx_wds_beacon_list);
    }

    close(nl_fd);
    return 0;
}

//CPE�˴�Ϊ����һ������
void rg_wds_beacon_join_net_cpe() {
	static unsigned long time_off;
	struct sysinfo info;

	sysinfo(&info);

	if (rg_gpio_info_t.gpio_lock_value == LOCK) {
		time_off = info.uptime;
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		time_off = info.uptime;
		return;
	}

	if (time_off == 0) {
		time_off = info.uptime;
	}

	if (info.uptime - time_off > BEACON_CHECK_TMIE) {
		time_off = info.uptime;
	} else {
		return;
	}

	struct wds_ssid_netid_t *p;
	p = wds_list_find_max_rssi(rg_ath_info_t.role);
	if (p == NULL) {
		DEBUG("can not find other ssid,sorry!");
		return;
	}
	DEBUG("now best ssid is %s ,ap rssi is %d,cpe rssi is %d",p->wds_ssid,p->rssi_ap,p->rssi_cpe);
	if (memcmp(p->wds_ssid,rg_ath_info_t.ssid,33) != 0) {
		if (rg_pair_info_heap_t == NULL) {
			rg_wds_ath_set_ssid(p->wds_ssid);
			rg_wds_ath_reload_wifi();
			rg_wds_ath_update(&rg_ath_info_t);
		} else {
			if (wds_list_rssi_compare(p,rg_pair_info_heap_t->pair_assioc_info_t.rssi)) {
				rg_wds_ath_set_ssid(p->wds_ssid);
				rg_wds_ath_reload_wifi();
				rg_wds_ath_update(&rg_ath_info_t);
			}
		}
	}
}

//ap�˴�Ϊ����һ������
void rg_wds_beacon_join_net_ap() {
	static unsigned long time_off;
	struct sysinfo info;

	sysinfo(&info);

	if (rg_gpio_info_t.gpio_lock_value == LOCK) {
		time_off = info.uptime;
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		time_off = info.uptime;
		return;
	}

	if (time_off == 0) {
		time_off = info.uptime;
	}

	if (info.uptime - time_off > BEACON_CHECK_TMIE) {
		time_off = info.uptime;
	} else {
		return;
	}

	struct wds_ssid_netid_t *p;
	p = wds_list_find_max_rssi(rg_ath_info_t.role);
	if (p == NULL) {
		return;
	}
	DEBUG("now best ssid is %s ,ap rssi is %d,cpe rssi is %d",p->wds_ssid,p->rssi_ap,p->rssi_cpe);
	if (memcmp(p->wds_ssid,rg_ath_info_t.ssid,33) != 0) {
		if (rg_pair_info_heap_t == NULL) {
			rg_wds_ath_set_ssid(p->wds_ssid);
			rg_wds_ath_reload_wifi();
			rg_wds_ath_update(&rg_ath_info_t);
		} else {
			if (wds_list_rssi_compare(p,rg_pair_info_heap_t->pair_assioc_info_t.rssi)) {
				rg_wds_ath_set_ssid(p->wds_ssid);
				rg_wds_ath_reload_wifi();
				rg_wds_ath_update(&rg_ath_info_t);
			}
		}
	}
}
