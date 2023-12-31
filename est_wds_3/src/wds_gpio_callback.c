#include "rg_wds.h"
#include "wds_gpio_debug.h"

struct dev_info rg_dev_info_t;
//rg_ath_info_t 该信息以配置文件为准，不以lock信息为准，设备实际是否生效也是配置文件决定的
struct ath_info rg_ath_info_t;

//不一定有对端信息，因此用指针表示
struct pair_dev_ath_info *rg_pair_info_heap_t = NULL;
struct gpio_info rg_gpio_info_t;
//beacon 接收到的信息组成的链表
struct wds_ssid_netid_t *wds_ssid_list_p = NULL;
//接收报文也会对这个进行处理，因此，需要保护该数据结构，因为设备模式，或者是锁定发生变化
//就要清除这个数据结构
pthread_mutex_t rg_pair_mtx;

pthread_mutex_t mtx_wds_beacon_list;

pthread_mutex_t mtx_wds_softversion_file;

pthread_mutex_t wds_fast_pair_mtx;

unsigned long time_count_all = 0;
unsigned long time_count_all_ms = 0;

struct uloop_timeout wds_gpio_timeout;

static void wds_gpio_function(void){
    int freq;
	static int g_sta_conn_status = FAIL;
    /* est310 sysled control */
	/*
    if (time_count_all % 10 == 9) {
        rg_wds_sysled_control(); 后续产品根据led情况考虑要不要适配
    } */
    /* update ath\mac\txpower\distance info */
    if (time_count_all % 50 == 20) {
        rg_wds_update_ath(&rg_dev_info_t, &rg_ath_info_t);
    }

    //不管是CPE还是AP都需要做的事情
    //获取wlanconfig list  信息，唯一获取STA信息的入口,每S一次
    if (time_count_all % 10 == 0) {
        g_sta_conn_status = rg_wds_pair_list_stations(rg_ath_info_t.ath_wds_name);
        GPIO_DEBUG("g_sta_conn_status is %s ", (g_sta_conn_status == SUCESS ? "TRUE" : "FALSE"));
		if (g_sta_conn_status == SUCESS) {
			del_pw_state_right_node();
			reset_oneclick_and_scanpair();
		}
	}

    #if 0
    //cpe任务
    //发送保活报文 5S 一次
    if (time_count_all % 50 == 2) {
        rg_wds_send_keep_date_cpe();
    }
    #endif
    
    //cpe任务
    //发送自身信息
    if (time_count_all % 100 == 3) {
        rg_wds_send_cpe_info();
    }

    #if 0
    //ap任务
    //处理保活 2S一次
    if (time_count_all % 50 == 4) {
        rg_wds_keep_data_respone();
    }
    #endif

    #if 0
    //AP接收到system信息，保存到本地
    if (time_count_all % 50 == 5) {
        rg_wds_sysinfo_write_ap();
    }
    #endif

    //更新hostname ip 地址,txpower,distance
    if (time_count_all % 50 == 10) {
        rg_wds_dev_update(&rg_dev_info_t);
    }

    //AP端同步system info 到所有CPE设备
    if (time_count_all % 100 == 11) {
        rg_wds_send_ap_info();
    }

    #if 0
    //cpe端更新system信息，假设很久没有收到信息之后就需要删除文件
    if (time_count_all % 50 == 12) {
        rg_wds_sysinfo_update_cpe();
    }
    #endif

    #if 0
    //200 毫秒 一次，尽可能快,同步版本信息
    if (time_count_all % 20 == 2) {
        rg_wds_version_send_ap();
        rg_wds_version_send_cpe();
    }
    #endif
    //每隔2S更新beacon扫描到的信息
    if (time_count_all % 20 == 0) {
        pthread_mutex_lock(&mtx_wds_beacon_list);
        wds_list_time_update();
        pthread_mutex_unlock(&mtx_wds_beacon_list);

		pthread_mutex_lock(&mtx_scan_dev_list);
		delete_overtime_scan_dev_node();
		pthread_mutex_unlock(&mtx_scan_dev_list);
    }

    //自动加入某个WDS网络
    /*
    if (time_count_all % 100 == 99) {
        rg_wds_beacon_join_net_cpe();
    }

    if (time_count_all % 100 == 98) {
        rg_wds_beacon_join_net_ap();
    }
    */
    //不管是CPE还是AP都需要做的事情,每隔3S处理一次,更新WLANCONFIG
    if (time_count_all % 30 == 2) {
        //这里面有可能会删除节点，程序定时器也有用到该节点，不保护会有问题!!
        pthread_mutex_lock(&rg_pair_mtx);
        rg_wds_pair_list_update();
        pthread_mutex_unlock(&rg_pair_mtx);
    }

    if (time_count_all % 20 == 3) {
        rg_wds_list_scanner();
		scan_dev_list_to_file();
    }

    //发送版本号信息
    #if 0
    if (time_count_all % 30 == 20) {
        rg_wds_soft_version_cpe_send();
        rg_wds_soft_version_ap_send();
    }
    #endif
    //UDP接收数据，采用非阻塞模式
    //if (time_count_all % 5 == 2) {
    //    rg_wds_udp_process();
    //}

    //发送全网广播信息
    //rg_wds_send_multi(time_count_all);

    //wifi 重启和设备重启
    //wifi 重启:cpe没有接受到ap端的保活报文，10分钟重启一次 一个小时重启设备
    //wifi 重启:ap没有接受到cpe端的保活报文，20分钟重启一次 两个小时重启设备
    if (time_count_all % 50 == 0) {
        /*
         * The following conditions no need to be considered for keepalive:
         * 1. dfs uci configuration is true;
         * 2. assoc linkdown ;
         * 3. if /proc/est/dfs_radar exist, no need to keepalive wds link.
         */

        if ( g_sta_conn_status == SUCESS ||(!is_dfs_file_exist()) && rg_wds_func_test_flag() == false) {
            GPIO_DEBUG("continue keep alive");
            rg_wds_pair_reboot();
        } else {
            GPIO_DEBUG("reset keep alive!");
            rg_wds_rst_kpl_param();
        }
    }

    if (time_count_all % 50 == 0) {
        get_trigger_dfs_channel_time();
    }


	if (time_count_all % 50 == 0){
		dfs_switch_control(g_sta_conn_status);
	}

	if(time_count_all % 51 == 0){
		update_beacon_info();
		printf("g_sta_conn_status=%d\n", g_sta_conn_status);
		bcn_expand_info_switch(g_sta_conn_status);
	}

}

void wds_gpio_run(void)
{
    wds_gpio_function();
    wds_gpio_timeout.cb = wds_gpio_run;
    uloop_timeout_set(&wds_gpio_timeout, 100);
    time_count_all_ms++;
    time_count_all++;
}

