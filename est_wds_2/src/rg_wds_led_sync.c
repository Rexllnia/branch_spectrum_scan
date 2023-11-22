#include "rg_wds.h"

#define CLOCKID CLOCK_REALTIME


void rg_wds_led_action(char action) {
	if (action == SYNC_CLEAR) {
		system("led_send_message \"wds_sync;clear\" >/dev/null");
	}

	if (action == SYNC_END) {
		system("led_send_message \"wds_sync;end\" >/dev/null");
	}

	if (action == SYNC_BEGIN) {
		system("led_send_message \"wds_sync;begin\" >/dev/null");
	}
}

void rg_wds_send_sync_led_data_fill_cpe(struct wds_sync_led_packet *sync_led_p,char atcion,struct pair_dev_ath_info * p) {
	unsigned char *tmp = (unsigned char *)p->mac;
	memset(sync_led_p,0,sizeof(struct wds_sync_led_packet));
	sync_led_p->role = rg_ath_info_t.role;
	sync_led_p->lock = rg_gpio_info_t.gpio_lock_value;
	sync_led_p->unuse = 0xaa;
	sync_led_p->unuse2 = 0xaa;
	memcpy(sync_led_p->name,"abcd",strlen("abcd"));
	sync_led_p->sync_flag = atcion;
	//兼容旧版本
	sprintf(sync_led_p->bssid,"%02x:%02x:%02x:%02x:%02x:%02x",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]);
	sync_led_p->cpe_num = 1;
}

void rg_wds_send_sync_led_date(struct pair_dev_ath_info * p,char atcion)
{
	struct mac_ip_udp_wds_packet eth_heap_p;
	struct wds_sync_led_packet sync_led_p;
	char buf[2000];
	char i;

	rg_wds_send_date_head_init(&eth_heap_p);
	rg_wds_send_sync_led_data_fill_cpe(&sync_led_p,atcion,p);

	memset(buf,0,sizeof(buf));
	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
	memcpy(buf + sizeof(struct mac_ip_udp_wds_packet),&sync_led_p,sizeof(struct wds_sync_led_packet));
	//连续发送5个，确保100%成功
	for (i = 0;i < 1; i++) {
		rg_send_raw_date(rg_ath_info_t.ath_wsd_name,sizeof(struct mac_ip_udp_wds_packet) + sizeof(struct wds_sync_led_packet),buf,p->mac);
	}
}

void rg_wds_sync_led() {
	static char flag = 0;
	char mac[6];
	char len,i;
	struct pair_dev_ath_info * p;

	if (rg_pair_info_heap_t == NULL) {
		goto bak;
	}

	if (flag == 1) {
		return;
	}

	flag = 1;
	//针对 301 和 302的处理
	if (rg_wds_est_is_phy_key(rg_dev_info_t.dev_type) == true) {
		//AP没有锁定，CPE中任意一台没有锁定，就认为要继续同步
		if (rg_gpio_info_t.gpio_lock_value == UNLOCK || rg_wds_lock_status_check() == UNLOCK) {
			if (rg_ath_info_t.role == MODE_AP) {
				///*
				//定时器是异步调用，需要保护该数据结构
				pthread_mutex_lock(&rg_pair_mtx);
				len = rg_wds_pair_list_len();
				pthread_mutex_unlock(&rg_pair_mtx);

				for (i = 0;i < len; i++) {
					rg_wds_led_action(SYNC_BEGIN);

					pthread_mutex_lock(&rg_pair_mtx);
					p = rg_pair_info_heap_t;
					while (p) {
						rg_wds_send_sync_led_date(p,SYNC_BEGIN);
						p = p->next;
					}
					pthread_mutex_unlock(&rg_pair_mtx);

					usleep(500000);

					rg_wds_led_action(SYNC_END);

					pthread_mutex_lock(&rg_pair_mtx);
					p = rg_pair_info_heap_t;
					while (p) {
						rg_wds_send_sync_led_date(p,SYNC_END);
						p = p->next;
					}
					pthread_mutex_unlock(&rg_pair_mtx);
					usleep(500000);
				}
				//*/
			}
		}else {
			if (rg_ath_info_t.role == MODE_AP) {
				rg_wds_led_action(SYNC_CLEAR);
				pthread_mutex_lock(&rg_pair_mtx);
				p = rg_pair_info_heap_t;
				while (p) {
					rg_wds_send_sync_led_date(p,SYNC_CLEAR);
					p = p->next;
				}
				pthread_mutex_unlock(&rg_pair_mtx);
			}
		}

	}

bak:
	flag = 0;
}

void rg_wds_sysled_control(void)
{
    char buf[20];

    memset(buf, 0, sizeof(buf));
    rg_wds_misc_read_file(DEV_FILE_MODEL, buf, sizeof(buf));
    if (strncmp(buf, "EST310", strlen("EST310")) == 0) {
        if (rg_ath_info_t.role == MODE_AP) {
            rg_wds_led_action(SYNC_CLEAR);
            rg_wds_led_action(SYNC_BEGIN);
        } else if (rg_ath_info_t.role == MODE_CPE) {
            rg_wds_led_action(SYNC_CLEAR);
            rg_wds_led_action(SYNC_BEGIN);
            sleep(1);
            rg_wds_led_action(SYNC_END);
        }
    }
}

void rg_wds_led_timer()
{
	timer_t timerid;
	struct sigevent evp;

	memset(&evp, 0, sizeof(struct sigevent));	//清零初始化

	evp.sigev_value.sival_int = 111;		//也是标识定时器的，这和timerid有什么区别？回调函数可以获得
	evp.sigev_notify = SIGEV_THREAD;		//线程通知的方式，派驻新线程
	evp.sigev_notify_function = rg_wds_sync_led;	//线程函数地址

	if (timer_create(CLOCKID, &evp, &timerid) == -1)
	{
		perror("fail to timer_create");
		exit(-1);
	}

	struct itimerspec it;
	it.it_interval.tv_sec = 3;	//间隔3s
	it.it_interval.tv_nsec = 0;
	it.it_value.tv_sec = 1;
	it.it_value.tv_nsec = 0;

	DEBUG("rg_wds_led_timer");

	if (timer_settime(timerid, 0, &it, NULL) == -1)
	{
		perror("fail to timer_settime");
		exit(-1);
	}
}

void rg_wds_get_sync_led_date (char *date) {
	struct wds_sync_led_packet* receve_date;

	if (rg_ath_info_t.role == MODE_AP) {
		return;
	}
	receve_date = (struct wds_sync_led_packet*)date;
	if (receve_date->sync_flag == SYNC_BEGIN) {
		rg_wds_led_action(SYNC_BEGIN);
	} else if (receve_date->sync_flag == SYNC_END) {
		rg_wds_led_action(SYNC_END);
	} else if (receve_date->sync_flag == SYNC_CLEAR) {
		rg_wds_led_action(SYNC_CLEAR);
	}
}
