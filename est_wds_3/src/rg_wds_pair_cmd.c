#include "rg_wds.h"

extern pthread_mutex_t mtx_rg_wds_all_info;
extern struct dev_multi_info *rg_wds_all_info;

void rg_wds_mac_2_softver (char *mac,char *softver) {
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
	char *start_addr=NULL;
	int verlen = 0;
    while (p != NULL) {
        if (strcasecmp(p->sys_mac, mac) == 0) {
            strcpy(softver,p->software_version);
			GPIO_DEBUG("tipc----softver:%s", softver);
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

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

