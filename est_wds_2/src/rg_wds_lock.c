#include "rg_wds.h"

void rg_wds_lock_send_data_fill(struct wds_date_head *lock_notify_data) {
    memset(lock_notify_data,0,sizeof(struct wds_date_head));
    lock_notify_data->role = rg_ath_info_t.role;
    lock_notify_data->lock = rg_gpio_info_t.gpio_lock_value;
    lock_notify_data->unuse = 0xaa;
    lock_notify_data->unuse2 = 0xaa;
    memcpy(lock_notify_data->bssid,rg_dev_info_t.sys_mac,6);
    memcpy(lock_notify_data->name,"abcd",strlen("abcd"));
    lock_notify_data->sync_flag = SYNC_LOCK;
}

void rg_wds_send_ap_lock_all(struct pair_dev_ath_info *p) {
    struct mac_ip_udp_wds_packet eth_heap_p;
    struct wds_date_head lock_notify_data;
    char buf[2000];
    char i;

    memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
    memset(&lock_notify_data,0,sizeof(struct wds_date_head));

    rg_wds_send_date_head_init(&eth_heap_p);
    rg_wds_lock_send_data_fill(&lock_notify_data);

    memset(buf,0,sizeof(buf));
    memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
    memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&lock_notify_data,sizeof(struct wds_date_head));
    for (i = 0;i < 5;i++) {
        rg_send_raw_date(rg_ath_info_t.ath_wsd_name,sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_date_head),buf,p->mac);
    }
}

void rg_wds_send_ap_lock() {
    struct pair_dev_ath_info *p = NULL;
    char i;

    //为了确保成功，会多发送报文
    for (i = 0;i < 10 ;i++) {
        p = rg_pair_info_heap_t;
        while (p) {
            rg_wds_send_ap_lock_all(p);
            p = p->next;
            usleep(1000*10);
        }
        //间隔100毫秒
        usleep(1000*100);
    }
}

void rg_wds_get_lock_cpe(char *data,int len) {
    if (rg_ath_info_t.role == MODE_AP) {
        return;
    }

    struct wds_info_packet_head *wds_head_p = (struct wds_info_packet_head *)((char *)data + 44);

    //判断头部信息有效
    if (rg_wds_misc_check_macaddress(wds_head_p->bssid) != 1) {
        return;
    }

    pthread_mutex_lock(&rg_pair_mtx);
    if (rg_pair_info_heap_t == NULL) {
        pthread_mutex_unlock(&rg_pair_mtx);
        return;
    }

    /* 校验桥接关联条件，来判断置上lock_flag */
    if (rg_cpe_check_setssid_condition(data) == -1) {
        pthread_mutex_unlock(&rg_pair_mtx);
        return;
    }

    if (memcmp(rg_pair_info_heap_t->pair_dev_info_t.sys_mac,wds_head_p->bssid,6) != 0) {
        memcpy(rg_pair_info_heap_t->pair_dev_info_t.sys_mac,wds_head_p->bssid,6);
    }
    rg_pair_info_heap_t->lock_flag = 1;
    pthread_mutex_unlock(&rg_pair_mtx);
    DEBUG("SMB UDP =====> ####mode=%s lock_flag=%d####", wds_head_p->role == 1 ? "AP" : "CPE", rg_pair_info_heap_t->lock_flag);
}

void rg_wds_lock_ap() {
    char lock_flag;

    if (rg_gpio_info_t.gpio_event & (1<<UNLOOK_LOOK_EVENT_BIT)) {
        //0 表示都是新版本，1表示有新的也有旧的
        lock_flag = rg_wds_version_cpe_check();

        if (lock_flag == 0) {
            //通告所有CPE，AP端要上锁了
            rg_wds_send_ap_lock();
            char buf[33];
            memset(buf,0,sizeof(buf));
            sprintf(buf,"@Ruijie-wds-%02x%02x",
                                rg_dev_info_t.sys_mac[4],
                                rg_dev_info_t.sys_mac[5]);
            DEBUG("buf %s",buf);
            rg_wds_ath_set_ssid(buf);
            rg_wds_ath_reload_wifi();
            rg_wds_ath_update(&rg_ath_info_t);
        } else {
            rg_wds_ap_add_maclist();
            //重启wifi会导致设备下线
            //rg_wds_ath_reload_wifi();
            rg_wds_ath_update(&rg_ath_info_t);
        }
    }
}

void rg_wds_lock_cpe() {
    char lock_flag;

    if (rg_gpio_info_t.gpio_event & (1<<UNLOOK_LOOK_EVENT_BIT)) {
        //0 表示都是新版本，1表示有新的也有旧的
        lock_flag = rg_pair_info_heap_t->version_flag;

        //lock_flag 1 表明之前的修改SSID是AP通知的
        if (lock_flag == 1) {
            DEBUG("ap nofity ,need to lock the ap");
        } else if (strcmp(rg_ath_info_t.ssid,DEF_SSID) != 0){
            //锁BSSID
            DEBUG("ap is lock long long ago,rg_ath_info_t %s DEF_SSID %s",rg_ath_info_t.ssid,DEF_SSID);
        } else {
            DEBUG("set ssid");
            rg_wds_cpe_set_bssid();
        }
    }
}

char rg_wds_cpe_get_ap_lock() {
    if (rg_pair_info_heap_t == NULL) {
        return;
    }

    if (rg_ath_info_t.role == MODE_AP) {
        return;
    }

    if (rg_pair_info_heap_t->version_flag == 1 && rg_pair_info_heap_t->lock_flag == 1) {
        char buf[33];
        memset(buf,0,sizeof(buf));
        dump_date(rg_pair_info_heap_t->pair_dev_info_t.sys_mac,6);
        sprintf(buf,"@Ruijie-wds-%02x%02x",
                            rg_pair_info_heap_t->pair_dev_info_t.sys_mac[4],
                            rg_pair_info_heap_t->pair_dev_info_t.sys_mac[5]);
        DEBUG("buf %s",buf);
        rg_wds_ath_set_ssid(buf);
        rg_wds_ath_reload_wifi();
        rg_wds_ath_update(&rg_ath_info_t);
        /*
         * /etc/rg_config/single/est_wirelss.json not match with uci
         * fixbug 537832
         */
        rg_wds_modify_est_wireless_file();
        sleep(1);
        rg_pair_info_heap_t->lock_flag = 0;
    }
}

char rg_wds_lock() {
    if (rg_pair_info_heap_t == NULL) {
        return;
    }

    if (rg_ath_info_t.role == MODE_CPE) {
        rg_wds_lock_cpe();
    }

    if (rg_ath_info_t.role == MODE_AP) {
        rg_wds_lock_ap();
    }
}

char rg_wds_unlock() {
    //处理LOCK改变
    if (rg_gpio_info_t.gpio_event & (1<<LOOK_UNLOOK_EVENT_BIT)) {
        DEBUG("lock_2_unlock");
        rg_wds_lock_2_unlock(&rg_ath_info_t);
        rg_wds_ath_reload_wifi();
        rg_wds_ath_update(&rg_ath_info_t);
        //清全网信息
        rg_wds_clear_all_list();
    }
}

void rg_wds_lock_status_update(char *data) {
    if (rg_pair_info_heap_t == NULL) {
        return;
    }

    pthread_mutex_lock(&rg_pair_mtx);
    struct wds_date_head *wds_receve;
    char *mac;
    struct pair_dev_ath_info *p = rg_pair_info_heap_t;

    mac = data + 6;
    wds_receve = (struct wds_packet *)((u_char *)data + 44);

    while (p) {
        if (memcmp(mac,p->mac,6) == 0) {
            p->lock_info_t.gpio_lock_value = wds_receve->lock;
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&rg_pair_mtx);
}

char rg_wds_lock_status_check() {
    pthread_mutex_lock(&rg_pair_mtx);
    struct pair_dev_ath_info *p = rg_pair_info_heap_t;

    while (p) {
        if (p->lock_info_t.gpio_lock_value == UNLOCK) {
            pthread_mutex_unlock(&rg_pair_mtx);
            return UNLOCK;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&rg_pair_mtx);
    return LOCK;
}

void rg_wds_lock_gpio_process() {
    if (rg_wds_est_is_phy_key(rg_dev_info_t.dev_type) == true) {
        //每1s 检查 GPIO,如果发生变化，重要数据结构全部初始化,除了代表设备的和ATH的
        rg_wds_gpio_process(&rg_gpio_info_t,&rg_ath_info_t);
        if (rg_gpio_info_t.gpio_event != 0) {
            DEBUG("rg_gpio_info_t->gpio_event %x",rg_gpio_info_t.gpio_event);
            rg_wds_lock();
            rg_wds_unlock();
            rg_wds_process_gpio_wireless_config(&rg_gpio_info_t,&rg_ath_info_t);
            rg_gpio_info_t.gpio_event = 0;
            /*
             * /etc/rg_config/single/est_wirelss.json not match with uci
             * fixbug 537832
             */
            rg_wds_modify_est_wireless_file();
        }
    }
}
