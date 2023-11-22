#include "rg_wds.h"
#include "wds_gpio_debug.h"

struct dev_info rg_dev_info_t;
//rg_ath_info_t ����Ϣ�������ļ�Ϊ׼������lock��ϢΪ׼���豸ʵ���Ƿ���ЧҲ�������ļ�������
struct ath_info rg_ath_info_t;

//��һ���жԶ���Ϣ�������ָ���ʾ
struct pair_dev_ath_info *rg_pair_info_heap_t = NULL;
struct gpio_info rg_gpio_info_t;
//beacon ���յ�����Ϣ��ɵ�����
struct wds_ssid_netid_t *wds_ssid_list_p = NULL;
//���ձ���Ҳ���������д�����ˣ���Ҫ���������ݽṹ����Ϊ�豸ģʽ�����������������仯
//��Ҫ���������ݽṹ
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
        rg_wds_sysled_control(); ������Ʒ����led�������Ҫ��Ҫ����
    } */
    /* update ath\mac\txpower\distance info */
    if (time_count_all % 50 == 20) {
        rg_wds_update_ath(&rg_dev_info_t, &rg_ath_info_t);
    }

    //������CPE����AP����Ҫ��������
    //��ȡwlanconfig list  ��Ϣ��Ψһ��ȡSTA��Ϣ�����,ÿSһ��
    if (time_count_all % 10 == 0) {
        g_sta_conn_status = rg_wds_pair_list_stations(rg_ath_info_t.ath_wds_name);
        GPIO_DEBUG("g_sta_conn_status is %s ", (g_sta_conn_status == SUCESS ? "TRUE" : "FALSE"));
		if (g_sta_conn_status == SUCESS) {
			del_pw_state_right_node();
			reset_oneclick_and_scanpair();
		}
	}

    #if 0
    //cpe����
    //���ͱ���� 5S һ��
    if (time_count_all % 50 == 2) {
        rg_wds_send_keep_date_cpe();
    }
    #endif
    
    //cpe����
    //����������Ϣ
    if (time_count_all % 100 == 3) {
        rg_wds_send_cpe_info();
    }

    #if 0
    //ap����
    //������ 2Sһ��
    if (time_count_all % 50 == 4) {
        rg_wds_keep_data_respone();
    }
    #endif

    #if 0
    //AP���յ�system��Ϣ�����浽����
    if (time_count_all % 50 == 5) {
        rg_wds_sysinfo_write_ap();
    }
    #endif

    //����hostname ip ��ַ,txpower,distance
    if (time_count_all % 50 == 10) {
        rg_wds_dev_update(&rg_dev_info_t);
    }

    //AP��ͬ��system info ������CPE�豸
    if (time_count_all % 100 == 11) {
        rg_wds_send_ap_info();
    }

    #if 0
    //cpe�˸���system��Ϣ������ܾ�û���յ���Ϣ֮�����Ҫɾ���ļ�
    if (time_count_all % 50 == 12) {
        rg_wds_sysinfo_update_cpe();
    }
    #endif

    #if 0
    //200 ���� һ�Σ������ܿ�,ͬ���汾��Ϣ
    if (time_count_all % 20 == 2) {
        rg_wds_version_send_ap();
        rg_wds_version_send_cpe();
    }
    #endif
    //ÿ��2S����beaconɨ�赽����Ϣ
    if (time_count_all % 20 == 0) {
        pthread_mutex_lock(&mtx_wds_beacon_list);
        wds_list_time_update();
        pthread_mutex_unlock(&mtx_wds_beacon_list);

		pthread_mutex_lock(&mtx_scan_dev_list);
		delete_overtime_scan_dev_node();
		pthread_mutex_unlock(&mtx_scan_dev_list);
    }

    //�Զ�����ĳ��WDS����
    /*
    if (time_count_all % 100 == 99) {
        rg_wds_beacon_join_net_cpe();
    }

    if (time_count_all % 100 == 98) {
        rg_wds_beacon_join_net_ap();
    }
    */
    //������CPE����AP����Ҫ��������,ÿ��3S����һ��,����WLANCONFIG
    if (time_count_all % 30 == 2) {
        //�������п��ܻ�ɾ���ڵ㣬����ʱ��Ҳ���õ��ýڵ㣬��������������!!
        pthread_mutex_lock(&rg_pair_mtx);
        rg_wds_pair_list_update();
        pthread_mutex_unlock(&rg_pair_mtx);
    }

    if (time_count_all % 20 == 3) {
        rg_wds_list_scanner();
		scan_dev_list_to_file();
    }

    //���Ͱ汾����Ϣ
    #if 0
    if (time_count_all % 30 == 20) {
        rg_wds_soft_version_cpe_send();
        rg_wds_soft_version_ap_send();
    }
    #endif
    //UDP�������ݣ����÷�����ģʽ
    //if (time_count_all % 5 == 2) {
    //    rg_wds_udp_process();
    //}

    //����ȫ���㲥��Ϣ
    //rg_wds_send_multi(time_count_all);

    //wifi �������豸����
    //wifi ����:cpeû�н��ܵ�ap�˵ı���ģ�10��������һ�� һ��Сʱ�����豸
    //wifi ����:apû�н��ܵ�cpe�˵ı���ģ�20��������һ�� ����Сʱ�����豸
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

