#include "rg_wds.h"

char debug = 1;
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

int main()
{
	char ret;
	pthread_t thread_wds_receve_date;
	pthread_t thread_wds_receve_beacon;
	pthread_t thread_wds_get_udp_message;

	unsigned long time_count_all = 0;
	unsigned long time_count_all_ms = 0;

	rg_wds_dev_init(&rg_dev_info_t);
	rg_wds_ath_init(&rg_dev_info_t,&rg_ath_info_t);
	//�豸�����䣬��301 302,301/2.0
	rg_wds_dev_match();

	//LED��ͬ������������̨ʹ�ö�ʱ��
	rg_wds_led_timer();

	//ץ������
	if (0 != pthread_create(&thread_wds_receve_date,NULL,rg_wds_revece_pactek_init,NULL)) {
		printf("%s %d error \n",__func__,__LINE__);
	}

	//��ȡSSID��Ϣ
	if (0 != pthread_create(&thread_wds_receve_beacon,NULL,rg_wds_beacon_pthread,NULL)) {
		printf("%s %d error \n",__func__,__LINE__);
	}

	//��ȡSSID��Ϣ
	if (0 != pthread_create(&thread_wds_get_udp_message,NULL,rg_wds_udp_process,NULL)) {
		printf("%s %d error \n",__func__,__LINE__);
	}

    DEBUG("sizeof %d",sizeof(struct dev_multi_info));

	while (1) {
        /* est310 sysled control */
        if (time_count_all % 10 == 9) {
            rg_wds_sysled_control();
        }
        /* update ath\mac info */
        if (time_count_all % 50 == 20) {
            rg_wds_update_ath(&rg_dev_info_t, &rg_ath_info_t);
        }

		//lock��unlock��ap��sta�仯����
		if (time_count_all % 10 == 1) {
			rg_wds_lock_gpio_process();
		}

		//������CPE����AP����Ҫ��������
		//��ȡwlanconfig list  ��Ϣ��Ψһ��ȡSTA��Ϣ�����,ÿSһ��
		if (time_count_all % 10 == 0) {
			rg_wds_pair_list_stations(rg_ath_info_t.ath_wsd_name);
		}

		//cpe����
		//���ͱ���� 5S һ��
		if (time_count_all % 50 == 2) {
			rg_wds_send_keep_date_cpe();
		}

		//cpe����
		//����������Ϣ
		if (time_count_all % 50 == 3) {
			rg_wds_send_cpe_info();
		}

		//ap����
		//������ 2Sһ��
		if (time_count_all % 50 == 4) {
			rg_wds_keep_data_respone();
		}

		//AP���յ�system��Ϣ�����浽����
		if (time_count_all % 50 == 5) {
			rg_wds_sysinfo_write_ap();
		}

		//����hostname ip ��ַ,txpower,distance
		if (time_count_all % 50 == 10) {
			rg_wds_dev_update(&rg_dev_info_t);
		}

		//AP��ͬ��system info ������CPE�豸
		if (time_count_all % 50 == 11) {
			rg_wds_send_ap_info();
		}

		//cpe�˸���system��Ϣ������ܾ�û���յ���Ϣ֮�����Ҫɾ���ļ�
		if (time_count_all % 50 == 12) {
			rg_wds_sysinfo_update_cpe();
		}

		//200 ���� һ�Σ������ܿ�,ͬ���汾��Ϣ
		if (time_count_all % 20 == 2) {
			rg_wds_version_send_ap();
			rg_wds_version_send_cpe();
		}

		//CPE�յ�������Ϣ�������豸
		if (time_count_all % 20 == 0) {
			rg_wds_cpe_get_ap_lock();
		}


		//ÿ��2S����beaconɨ�赽����Ϣ
		if (time_count_all % 20 == 0) {
			pthread_mutex_lock(&mtx_wds_beacon_list);
			wds_list_time_update();
			pthread_mutex_unlock(&mtx_wds_beacon_list);
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
		}

        //���Ͱ汾����Ϣ
        if (time_count_all % 30 == 20) {
            rg_wds_soft_version_cpe_send();
            rg_wds_soft_version_ap_send();
        }

        //UDP�������ݣ����÷�����ģʽ
        //if (time_count_all % 5 == 2) {
        //    rg_wds_udp_process();
        //}

        //����ȫ���㲥��Ϣ
        rg_wds_send_multi(time_count_all);

		//wifi �������豸����
		//wifi ����:cpeû�н��ܵ�ap�˵ı���ģ�6��������һ��
		//wifi ����:apû�н��ܵ�cpe�˵ı���ģ�20��������һ��
		if (time_count_all % 50 == 0) {
            if (rg_wds_func_test_flag() == false) {
                rg_wds_pair_reboot();
            }
		}
loop:
		time_count_all_ms++;
		time_count_all++;
		//100ms
		usleep(1000*100);

	}
}
