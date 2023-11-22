#include "rg_wds.h"

#define DEV_GET_HOSTNAME_CMD         "uci get system.@system[0].hostname"
#define DEV_SYSMAC_ETH               "eth1"
#define DEV_IP_ADDRESS_INTERFACE     "br-wan"

char wds_get_dev_type(char *buf,char len)
{
	//memcpy(buf,DEV_300,strlen(DEV_300));
	rg_wds_misc_read_file(DEV_FILE_MODEL,buf,len);
}

char wds_get_dev_hardware_version(char *buf,char len)
{
	rg_wds_misc_read_file(DEV_FILE_HARDWARE_VERSION,buf,len);
}

char wds_get_dev_software_version(char *buf,char len)
{
	rg_wds_misc_read_file(DEV_FILE_SOFTWARE_VERSION,buf,len);
}

char wds_get_dev_sysmac(char *buf,char len)
{
	//rg_wds_misc_read_file(DEV_FILE_SYSMAC,buf,len);
	rg_wds_misc_get_mac(DEV_SYSMAC_ETH,buf);
}

char wds_get_dev_sn(char *buf,char len)
{
	rg_wds_misc_read_file(DEV_FILE_SN,buf,len);
}

char wds_get_dev_ip(unsigned int *ip)
{
	*ip = rg_wds_misc_get_iface_ip(DEV_IP_ADDRESS_INTERFACE);
}

void rg_wds_dev_update(struct dev_info *dev_info_t) {
	wds_get_dev_ip(&dev_info_t->ip);
	rg_wds_misc_get_uci_option(DEV_GET_HOSTNAME_CMD,dev_info_t->host_name,sizeof(dev_info_t->host_name));
}

char rg_wds_dev_init(struct dev_info *dev_info_t)
{
	memset(dev_info_t,0,sizeof(struct dev_info));
	wds_get_dev_type(dev_info_t->dev_type,sizeof(dev_info_t->dev_type) - 1);
	wds_get_dev_hardware_version(dev_info_t->hardware_version,sizeof(dev_info_t->hardware_version));
    wds_get_dev_software_version(dev_info_t->software_version,sizeof(dev_info_t->software_version));
	wds_get_dev_sysmac(dev_info_t->sys_mac,sizeof(dev_info_t->sys_mac) - 1);
	wds_get_dev_sn(dev_info_t->sn,sizeof(dev_info_t->sn) - 1);
	wds_get_dev_ip(&dev_info_t->ip);
	rg_wds_misc_get_uci_option(DEV_GET_HOSTNAME_CMD,dev_info_t->host_name,sizeof(dev_info_t->host_name) - 1);
}

char rg_wds_dev_match()
{
	//char buf[20];
	//memset(buf,0,sizeof(buf));
    //rg_wds_json_first(GPIO_CONF_FILE,WDS_TPYT_ID,buf,sizeof(buf));
    //return;
	if (rg_wds_est_is_phy_key(rg_dev_info_t.dev_type) == true) {
		rg_wds_gpio_init(&rg_gpio_info_t);
		rg_wds_gpio_read(&rg_gpio_info_t);

		DEBUG("gpio_mode_value %d gpio_lock_value %d",rg_gpio_info_t.gpio_mode_value,rg_gpio_info_t.gpio_lock_value);
		if (rg_gpio_info_t.gpio_lock_value == UNLOCK) {
            /* 如果设备UNLOCK状态，即便是设置过ssid，设备重启也要清除所有配置，目的是下电的情况下拨为unlock，起机必须清除配置 */
			if (strcmp(rg_ath_info_t.ssid,DEF_SSID) !=0 || rg_wds_ath_bssid_check() \
				|| rg_ath_info_t.option_macfilter ||rg_ath_info_t.list_maclist) {
				DEBUG("rg_ath_info_t.ssid %s DEF_SSID %s gpio_lock_value %d",rg_ath_info_t.ssid,DEF_SSID,rg_gpio_info_t.gpio_lock_value);
				DEBUG("bssid");
				dump_date(rg_ath_info_t.bssid,6);
				DEBUG("option_macfilter %d list_maclist %d",rg_ath_info_t.option_macfilter,rg_ath_info_t.list_maclist);
				rg_wds_lock_2_unlock(&rg_ath_info_t);
				rg_wds_ath_reload_wifi();
				rg_wds_ath_init(&rg_dev_info_t,&rg_ath_info_t);
			}
		}

		if (rg_gpio_info_t.gpio_mode_value != rg_ath_info_t.role) {
			//恢复为默认SSID
			DEBUG("rg_gpio_info_t.gpio_mode_value %d rg_ath_info_t.role %d",rg_gpio_info_t.gpio_mode_value,rg_ath_info_t.role);
			if (rg_gpio_info_t.gpio_mode_value == MODE_AP) {
				rg_wds_sta_2_ap(&rg_ath_info_t);
			} else if (rg_gpio_info_t.gpio_mode_value == MODE_CPE) {
				rg_wds_ap_2_sta(&rg_ath_info_t);
			}

			rg_wds_ath_reload_wifi();
			rg_wds_ath_init(&rg_dev_info_t,&rg_ath_info_t);
		}
	} else if (rg_wds_est_is_phy_key(rg_dev_info_t.dev_type) == false) {
		rg_gpio_info_t.gpio_lock_num = LOCK_GPIO;
		rg_gpio_info_t.gpio_mode_num = MODE_GPIO;

		rg_gpio_info_t.gpio_lock_value = LOCK;
		rg_gpio_info_t.gpio_mode_value = rg_ath_info_t.role;

		rg_gpio_info_t.gpio_lock_value_last = rg_gpio_info_t.gpio_lock_value;
		rg_gpio_info_t.gpio_mode_value_last= rg_gpio_info_t.gpio_mode_value;
		DEBUG("gpio_lock_value %d gpio_mode_value %d",rg_gpio_info_t.gpio_lock_value,rg_gpio_info_t.gpio_mode_value);
	}
}

void rg_wds_dev_reboot () {
	DEBUG("reboot dev");
	system("reboot");
}
