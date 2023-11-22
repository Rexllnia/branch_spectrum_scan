#include "rg_wds.h"

//通告AP升级当前的WDS网络
void rg_wds_send_update_cpe()
{
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}

    struct mac_ip_udp_wds_packet eth_heap_p;
    struct wds_date_head wds_head_p;
    char buf[2000]; 
    char i;

    memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
    memset(&wds_head_p,0,sizeof(struct wds_date_head));

    rg_wds_send_date_head_init(&eth_heap_p);
    rg_wds_version_wds_date_head_fill(&wds_head_p,SYNC_SOFTWARE_UPDATE);

    memset(buf,0,sizeof(buf));
    memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
    memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&wds_head_p,sizeof(struct wds_date_head));

    for (i = 0;i < 50;i++) {
        rg_send_raw_date(rg_ath_info_t.ath_wsd_name,sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head),buf,rg_pair_info_heap_t->mac);
    }
}

int rg_wds_get_version(char *buf)
{
    char verson[10];
    char *tmp = buf;
    char i = 0;

    if (strlen(buf) == 0) {
        return 0;
    }

    //AP_3.0(1)B2P10,Release(05202723) ，获取05202723这个字符串，并转换为数字，才能比对大小
    for (i; i < strlen(buf);i++) {
        if (buf[i] == '(' && (tmp - buf) > 10) {
            break;
        }
        tmp++;  
    }
    
    i++;
    
    DEBUG("tmp %s",tmp);
    memset(verson,0,sizeof(verson));
    if (buf[i] == '0') {
        memcpy(verson,buf + i + 1,7);
    } else {
        memcpy(verson,buf + i,8);
    }

    DEBUG("verson %s",verson);

    return atoi(verson);
}

struct dev_info * rg_wds_find_best_version() {
    struct dev_info *tmp = NULL;
    int version_dst = 0;
    int version_src = 0;
    
    pthread_mutex_lock(&rg_pair_mtx);
    //与所有关联的设备比较
    struct pair_dev_ath_info *p = rg_pair_info_heap_t;
    while (p) {
        version_src = rg_wds_get_version(p->pair_dev_info_t.software_version);
        if (version_src > version_dst) {
            version_dst = version_src;
            tmp = (struct dev_info *)&p->pair_dev_info_t;
        }
        p = p->next;
    }
    
    //与AP自己比较
    version_src = rg_wds_get_version(rg_dev_info_t.software_version);
    if (version_src > version_dst) {
        version_dst = version_src;
        tmp = &rg_dev_info_t;
    }
    
    if (tmp != NULL && version_dst != 0) {
        DEBUG("the best version %s",tmp->software_version);
        struct dev_info *ret;
 		ret = malloc(sizeof(struct dev_info));
		memset(ret,0,sizeof(struct dev_info));
        memcpy(ret,tmp,sizeof(struct dev_info));
        pthread_mutex_unlock(&rg_pair_mtx);
        return ret;
    } else {
        pthread_mutex_unlock(&rg_pair_mtx);
        return NULL;
    }
}

void rg_wds_update_send_ap(struct pair_dev_ath_info *dst_p,struct dev_info *src_p) {
	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_date_head wds_head_p;
    struct wds_update_version_packet update_p;
	char buf[2000];	
	char i;

	memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
	memset(&wds_head_p,0,sizeof(struct wds_date_head));
    memset(&update_p,0,sizeof(struct wds_update_version_packet));

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_version_wds_date_head_fill(&wds_head_p,SYNC_SOFTWARE_UPDATE);
    update_p.src_ip = src_p->ip;
    memcpy(update_p.softverson,src_p->software_version,sizeof(src_p->software_version));
    
	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&wds_head_p,sizeof(struct wds_date_head));
    memcpy(buf + sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head),\
            &update_p,sizeof(struct wds_update_version_packet));
    
	for (i = 0;i < 5;i++) {
		rg_send_raw_date(rg_ath_info_t.ath_wsd_name,sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head),buf,dst_p->mac);
	}
}

void rg_wds_ap_send_update_cmd_2_cpe(struct dev_info *dev_best_p)
{
	if (rg_pair_info_heap_t == NULL ) {
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}
    char i;
    pthread_mutex_lock(&rg_pair_mtx);
    for (i = 0;i<10;i++) {
        struct pair_dev_ath_info *p = rg_pair_info_heap_t;
        while (p) {
            //目标版本不需要升级
            if (&p->pair_dev_info_t == dev_best_p) {
                goto loop;
            }
            
            //版本低的升级
            if (rg_wds_get_version(dev_best_p->software_version) <= rg_wds_get_version(p->pair_dev_info_t.software_version)) {
                goto loop;
            }

            rg_wds_update_send_ap(p,dev_best_p);
 loop:
            p = p->next;
        }
    }
    pthread_mutex_unlock(&rg_pair_mtx);
}

//AP端如果是被动触发升级的话
void rg_wds_get_update_cmd_ap() {
    static char flag = 0;
    
    DEBUG("flag %d",flag);
    if (flag == 1) {
        return;
    }

    if (flag == 0) {
        flag = 1;
    }
    DEBUG("flag %d",flag);
    pthread_t thread_wds_update;
	//抓包程序
	if (0 != pthread_create(&thread_wds_update,NULL,rg_wds_ap_update_process,&flag)) {
		printf("%s %d error \n",__func__,__LINE__);
	}
}

void rg_wds_cpe_update_process(void *arg)
{
    char buf[100];
    struct in_addr in;   
    unsigned int *p = arg;

    in.s_addr = *(p + 1); 
    memset(buf,0,sizeof(buf));   
    sprintf(buf,"wds_update.sh %s",inet_ntoa(in));

    DEBUG("buf %s",buf);
    system(buf);

    *p = 0;
}

//CPE是被动触发升级动作
//接受到升级指令，如果当前正在执行升级操作，则不做响应
void rg_wds_get_update_cmd_cpe(unsigned char *data,int data_len)
{
    struct wds_update_version_packet *update_cmd_p = ((char *)data + 44 + sizeof(struct wds_date_head));
    struct wds_date_head *version_data_p = (struct wds_date_head *)((char *)data + 44);
    static unsigned int arg[2];

    if (arg[0] == 1) {
        return;
    }

    if (arg[0] == 0) {
        arg[0] = 1;
    }
    
    //比对版本，除非本地比另外一台小，否则不升级,版本号有可能传输错误，所以一定要比对
    if (rg_wds_get_version(rg_dev_info_t.software_version) >= rg_wds_get_version(update_cmd_p->softverson)) {
        arg[0] = 0;
        return;
    }
    
    pthread_t thread_wds_update;

    arg[1] = update_cmd_p->src_ip;

	//抓包程序
	if (0 != pthread_create(&thread_wds_update,NULL,rg_wds_cpe_update_process,arg)) {
		DEBUG("error");
	}
    DEBUG("pthread_create sucess!!");
}

//AP端升级
void rg_wds_update_ap(struct dev_info *src_p) {
    struct in_addr in;
    char buf[100];

    in.s_addr = src_p->ip; 
    memset(buf,0,sizeof(buf));

    sprintf(buf,"wds_update.sh %s",inet_ntoa(in));
    DEBUG("buf %s",buf);
    system(buf);
}

void rg_wds_get_update_cmd(unsigned char *packet,int len)
{
    if (rg_ath_info_t.role == MODE_CPE) {
        rg_wds_get_update_cmd_cpe(packet,len);
    }
    
    if (rg_ath_info_t.role == MODE_AP) {
        rg_wds_get_update_cmd_ap();
    }
}

char rg_wds_cpe_version_cmp(struct dev_info *dev_best_p) {
    pthread_mutex_lock(&rg_pair_mtx);    
    struct pair_dev_ath_info *p = rg_pair_info_heap_t; 

    while (p) {
        //版本小
        if (rg_wds_get_version(dev_best_p->software_version) > rg_wds_get_version(p->pair_dev_info_t.software_version)) {
            pthread_mutex_unlock(&rg_pair_mtx);
            return 1;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&rg_pair_mtx);
    return 0;
}

void rg_wds_ap_update_process(void *arg)
{
    struct dev_info *dev_best_p = NULL;
    int i = 0;

    if (rg_pair_info_heap_t == NULL) {
        goto end;
    }

    if (dev_best_p == NULL) {
        dev_best_p = rg_wds_find_best_version();
    }

    if (dev_best_p == NULL) {
        DEBUG("can not find best softverson");
        goto end;
    }

    //发送信息到CPE
    rg_wds_ap_send_update_cmd_2_cpe(dev_best_p);
    while (1) {
        sleep(2);
        if (rg_wds_cpe_version_cmp(dev_best_p) == 0) {
            break;
        }
        
        //超过5分钟就不管了，AP先升级了再说
        if (i++ > 150) {
            break;
        }
    }
    //如果最新版本是AP，那么AP不需要升级，否则升级AP
    DEBUG("cpe %s ap %s",dev_best_p->software_version,rg_dev_info_t.software_version);
    if (rg_wds_get_version(dev_best_p->software_version) > rg_wds_get_version(rg_dev_info_t.software_version)) {
        rg_wds_update_ap(dev_best_p);
    }
end: 
    *(char *)arg = 0;
    if (dev_best_p != NULL) {
        free(dev_best_p);
    }
}
