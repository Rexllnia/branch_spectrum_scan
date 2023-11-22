#include "rg_wds.h"

extern pthread_mutex_t mtx_rg_wds_all_info;
extern struct dev_multi_info *rg_wds_all_info;

void rg_wds_sn_2_mac(char *sn,char *mac) {
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    while (p != NULL) {
        if (strcmp(p->sn,sn) == 0) {
            strcpy(mac,p->sys_mac);
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_send_cmd(char *cmd,char *sn) {
	struct mac_ip_udp_wds_packet eth_heap_p;
    char mac[6];
	char buf[2000];
	char flag = 0;
	char i = 0;
    int len = 0;

    memset(mac,0,sizeof(mac));

    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    while (p != NULL) {
        DEBUG("SN %s p->sn %s",sn,p->sn);
        if (strcmp(p->sn,sn) == 0) {
            switch_mac_char_2_hex(p->ath_mac,mac);
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&mtx_rg_wds_all_info);

    if (strlen(cmd) > 1200) {
        DEBUG("cmd %s len %d is error !!!!",cmd,strlen(cmd));
        return;
    }

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));

	rg_wds_send_date_head_init(&eth_heap_p);

	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
    len += sizeof(struct mac_ip_udp_wds_packet);

    rg_wds_to_dev_message(TYPE_SET,sn,buf + len,cmd);
    DEBUG("buf %s",buf + len);

    len += strlen(cmd);
    DEBUG("cmd %s",cmd);
    if (p == NULL) {
        rg_send_raw_date_2("br-wan",len,buf,NULL);
    } else {
        rg_send_raw_date_2("br-wan",len,buf,mac);
    }
}

void rg_wds_ext_cmd(void *arg) {
    char *cmd = (char *)arg;

    DEBUG("  cmd   %s",arg);
    system((char *)arg);
    pthread_detach(pthread_self());
    free(cmd);
}

void rg_wds_get_cmd(char *cmd) {
    pthread_t thread_wds_cmd;
    DEBUG("cmd %s",cmd);

    char *buf = NULL;

    buf = malloc(strlen(cmd) + 1);
    if (buf == NULL) {
        return;
    }

    memset(buf,0,strlen(cmd) + 1);

    memcpy(buf,cmd,strlen(cmd));

	if (0 != pthread_create(&thread_wds_cmd,NULL,rg_wds_ext_cmd,buf)) {
        printf("%s %d error \n",__func__,__LINE__);
	}
}
