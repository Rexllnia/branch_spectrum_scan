#include "rg_wds.h"

#define ATH_GET_CMD_MODE       "uci get wireless.@wifi-iface[0].mode"
#define ATH_GET_CMD_SSID       "uci get wireless.@wifi-iface[0].ssid"
#define ATH_GET_CMD_BSSID      "uci get wireless.@wifi-iface[0].bssid"
#define ATH_SET_CMD_SSID       "uci set wireless.@wifi-iface[0].ssid=%s"
#define ATH_SET_CMD_MODE       "uci set wireless.@wifi-iface[0].mode=%s"
#define ATH_SET_CMD_BSSID      "uci set wireless.@wifi-iface[0].bssid=\"%02x:%02x:%02x:%02x:%02x:%02x\""
#define ATH_CLAER_CMD_BSSID    "uci delete wireless.@wifi-iface[0].bssid"
#define ATH_GET_CMD_MACLIST       "uci get wireless.@wifi-iface[0].maclist"
#define ATH_GET_CMD_MACFILTER     "uci get wireless.@wifi-iface[0].macfilter"

#define ATH_CMD_CLEAR_MACLIST       "uci delete wireless.@wifi-iface[0].maclist"
#define ATH_CMD_ADD_MACLIST         "uci add_list wireless.@wifi-iface[0].maclist=\"%02x:%02x:%02x:%02x:%02x:%02x\""
#define ATH_CMD_CLEAR_MACFILTER     "uci delete wireless.@wifi-iface[0].macfilter"
#define ATH_CMD_ALLOW_MACFILTER     "uci set wireless.@wifi-iface[0].macfilter=\"allow\""

#define ATH_WDS_TYPE_CMD            "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""

#define EST_WIRELESS_UNFITY_FILE    "/etc/rg_config/single/est_wireless_%s.json"

#define EST_WIRELESS_GET_TXPOWER    "uci get wireless.%s.txpower"
#define EST_WIRELESS_GET_DISTANCE    "uci get wireless.%s.distance"

char rg_wds_ath_get_name(struct dev_info *dev_info_t,struct ath_info *ath_info_t)
{
    if (rg_wds_est_radio_type(dev_info_t->dev_type) == EST_2G) {
        memcpy(ath_info_t->ath_wsd_name, ATH_2G_WDS_NAME, strlen(ATH_2G_WDS_NAME));
        memcpy(ath_info_t->ath_managed_name, ATH_2G_MAG_NAME, strlen(ATH_2G_MAG_NAME));
        memcpy(ath_info_t->wifi_wsd_name, WIFI_2G_WDS_NAME, strlen(WIFI_2G_WDS_NAME));
    } else if (rg_wds_est_radio_type(dev_info_t->dev_type) == EST_5G) {
        memcpy(ath_info_t->ath_wsd_name, ATH_5G_WDS_NAME, strlen(ATH_5G_WDS_NAME));
        memcpy(ath_info_t->ath_managed_name, ATH_5G_MAG_NAME, strlen(ATH_5G_MAG_NAME));
        memcpy(ath_info_t->wifi_wsd_name, WIFI_5G_WDS_NAME, strlen(WIFI_5G_WDS_NAME));
    }
}

char rg_wds_ath_get_mac(struct ath_info *ath_info_t)
{
	char ret;

	//这个地方需要保证一定是成功获取到MAC地址
	while (1) {
		ret = rg_wds_misc_get_mac(ath_info_t->ath_wsd_name,ath_info_t->root_mac_hex);
		if (ret == SUCESS) {
			break;
		}
		sleep(1);
	}

	//转化为字符串
	memset(ath_info_t->ath_mac,0,sizeof(ath_info_t->ath_mac));
	/*
	sprintf(ath_info_t->ath_mac,"%02x:%02x:%02x:%02x:%02x:%02x",\
			ath_info_t->root_mac_hex[0],\
			ath_info_t->root_mac_hex[1],\
			ath_info_t->root_mac_hex[2],\
			ath_info_t->root_mac_hex[3],\
			ath_info_t->root_mac_hex[4],\
			ath_info_t->root_mac_hex[5]);
	*/
}

char rg_wds_ath_get_ssid(struct ath_info *ath_info_t)
{
	memset(ath_info_t->ssid,0,sizeof(ath_info_t->ssid));
	rg_wds_misc_get_uci_option(ATH_GET_CMD_SSID,ath_info_t->ssid,sizeof(ath_info_t->ssid));
}

char rg_wds_wifi_get_txpower(struct ath_info *ath_info_t)
{
    char buf[100];

    memset(buf,0,sizeof(buf));

    sprintf(buf,"iwlist %s txpower | grep Current | awk '{print $2}' | awk -F '=' '{print $2}'",rg_ath_info_t.ath_wsd_name);

	memset(ath_info_t->wds_txpower,0,sizeof(ath_info_t->wds_txpower));
	rg_wds_misc_get_uci_option(buf,ath_info_t->wds_txpower,sizeof(ath_info_t->wds_txpower));
}

char rg_wds_wifi_get_distance(struct ath_info *ath_info_t)
{
    char buf[50];
    memset(buf,0,sizeof(buf));

    sprintf(buf,EST_WIRELESS_GET_DISTANCE,rg_ath_info_t.wifi_wsd_name);

	memset(ath_info_t->wds_distance,0,sizeof(ath_info_t->wds_distance));

	rg_wds_misc_get_uci_option(buf,ath_info_t->wds_distance,sizeof(ath_info_t->wds_distance));
}

char rg_wds_ath_get_role(struct ath_info *ath_info_t)
{
	char buf[20];
	memset(buf,0,sizeof(buf));
	rg_wds_misc_get_uci_option(ATH_GET_CMD_MODE,buf,sizeof(buf));
	if (strcmp(buf,ATH_MODE_STA) == 0) {
		ath_info_t->role = MODE_CPE;
	} else if (strcmp(buf,ATH_MODE_AP) == 0) {
		ath_info_t->role = MODE_AP;
	} else {
		ath_info_t->role = MODE_UNKNOW;
	}
	//DEBUG("ath_info_t->role %d",ath_info_t->role);
}

char rg_wds_ath_bssid_check() {
	char tmp[6] = {0x0,0x0,0x0,0x0,0x0,0x0};
	if (memcmp(rg_ath_info_t.bssid,tmp,6) == 0) {
		return 0;
	}
	return 1;
}

char rg_wds_ath_get_macfilter(struct ath_info *ath_info_t)
{
	char buf[20];
	memset(buf,0,sizeof(buf));
	rg_wds_misc_get_uci_option(ATH_GET_CMD_MACFILTER,buf,sizeof(buf));
	DEBUG("buf %s",buf);
	if (strlen(buf) != 0) {
		ath_info_t->option_macfilter = 1;
	} else {
		ath_info_t->option_macfilter = 0;
	}
}

char rg_wds_ath_get_maclist(struct ath_info *ath_info_t)
{
	char buf[300];
	memset(buf,0,sizeof(buf));
	rg_wds_misc_get_uci_option(ATH_GET_CMD_MACLIST,buf,sizeof(buf));
	DEBUG("buf %s",buf);
	if (strlen(buf) != 0) {
		ath_info_t->list_maclist = 1;
	} else {
		ath_info_t->list_maclist = 0;
	}
}

char rg_wds_ath_get_bssid(struct ath_info *ath_info_t)
{
	char buf[20];
	memset(buf,0,sizeof(buf));
	rg_wds_misc_get_uci_option(ATH_GET_CMD_BSSID,buf,sizeof(buf));
	DEBUG("buf %s",buf);
	switch_mac_char_2_hex(buf,ath_info_t->bssid);
	dump_date(ath_info_t->bssid,6);
}

char rg_wds_update_ath(struct dev_info *dev_info_t, struct ath_info *ath_info_t)
{
    if (dev_info_t == NULL || ath_info_t == NULL) {
        DEBUG("dev_info_t or ath_info_t is NULL.");
        return FAIL;
    }

    memset(ath_info_t->ath_wsd_name, 0, sizeof(ath_info_t->ath_wsd_name));
    memset(ath_info_t->wifi_wsd_name, 0, sizeof(ath_info_t->wifi_wsd_name));
    memset(ath_info_t->ath_managed_name, 0, sizeof(ath_info_t->ath_managed_name));
    memset(ath_info_t->root_mac_hex, 0, sizeof(ath_info_t->root_mac_hex));

    rg_wds_ath_get_name(dev_info_t, ath_info_t);
    rg_wds_ath_get_mac(ath_info_t);
    rg_wds_ath_get_role(ath_info_t);
}

char rg_wds_ath_init(struct dev_info *dev_info_t,struct ath_info *ath_info_t)
{
	struct sysinfo info;
	sysinfo(&info);

	memset(ath_info_t,0,sizeof(struct ath_info));
	rg_wds_ath_get_name(dev_info_t,ath_info_t);
	rg_wds_ath_get_mac(ath_info_t);
	rg_wds_ath_get_ssid(ath_info_t);
	rg_wds_ath_get_role(ath_info_t);
	rg_wds_ath_get_bssid(ath_info_t);
	rg_wds_ath_get_maclist(ath_info_t);
	rg_wds_ath_get_macfilter(ath_info_t);
    rg_wds_wifi_get_txpower(ath_info_t);
    rg_wds_wifi_get_distance(ath_info_t);
}

char rg_wds_ath_update(struct ath_info *ath_info_t)
{
	rg_wds_ath_get_ssid(ath_info_t);
	rg_wds_ath_get_role(ath_info_t);
}


char rg_wds_ath_set_def_ssid(struct ath_info *ath_info_t)
{
	char buf[70];

	memset(buf,0,sizeof(buf));
	sprintf(buf,ATH_SET_CMD_SSID,DEF_SSID);
	rg_wds_misc_set_uci_config(buf);

    //统一框架还需要修改json文件
    memset(buf,0,sizeof(buf));
    sprintf(buf,EST_WIRELESS_UNFITY_FILE,rg_dev_info_t.sn);
    rg_wds_second_set(buf,"ssidList","ssidName",DEF_SSID);
}

char rg_wds_ath_set_ssid(char *ssid)
{
	char buf[70];

	memset(buf,0,sizeof(buf));
	sprintf(buf,ATH_SET_CMD_SSID,ssid);
	rg_wds_misc_set_uci_config(buf);

    //统一框架还需要修改json文件
    memset(buf,0,sizeof(buf));
    sprintf(buf,EST_WIRELESS_UNFITY_FILE,rg_dev_info_t.sn);
    rg_wds_second_set(buf,"ssidList","ssidName",ssid);
}

char rg_wds_ath_set_mode(struct ath_info *ath_info_t,char mode)
{
	char buf[70];

	memset(buf,0,sizeof(buf));
	if (mode == MODE_AP) {
		sprintf(buf,ATH_SET_CMD_MODE,MODE_VALUE_AP);
	} else if (mode == MODE_CPE) {
		sprintf(buf,ATH_SET_CMD_MODE,MODE_VALUE_CPE);
	}

	rg_wds_misc_set_uci_config(buf);
}

int rg_wds_ath_reload_wifi()
{
	system("kill -9 `ps | grep wifi | awk '{print $1}'`");
	system("wifi &");
	DEBUG("reload wifi");
	return SUCESS;
}

//
char rg_wds_lock_2_unlock(struct ath_info *ath_info_t)
{
	rg_wds_ath_set_def_ssid(ath_info_t);
	rg_wds_ap_clear_maclist();
	rg_wds_cpe_clear_bssid();
}

char rg_wds_unlock_2_lock(struct ath_info *ath_info_t)
{
	return;
}

char rg_wds_ap_2_sta(struct ath_info *ath_info_t)
{
	rg_wds_ath_set_mode(ath_info_t,MODE_CPE);
}

char rg_wds_sta_2_ap(struct ath_info *ath_info_t)
{
	rg_wds_ath_set_mode(ath_info_t,MODE_AP);
}

char rg_wds_process_gpio_wireless_config(struct gpio_info *rg_gpio_info_t,struct ath_info *ath_info_t)
{
	//处理模式改变
	if (rg_gpio_info_t->gpio_event & (1<<AP_STA_EVENT_BIT)) {
		DEBUG("ap_2_sta");
		rg_wds_ap_2_sta(ath_info_t);
		rg_wds_ath_update(&rg_ath_info_t);
		rg_wds_ath_reload_wifi();
        //清全网信息
        rg_wds_clear_all_list();
	} else if (rg_gpio_info_t->gpio_event & (1<<STA_AP_EVENT_BIT)) {
		DEBUG("sta_2_ap");
		rg_wds_sta_2_ap(ath_info_t);
		rg_wds_ath_update(&rg_ath_info_t);
		rg_wds_ath_reload_wifi();
        //清全网信息
        rg_wds_clear_all_list();
	}
}

//写入配置
void rg_wds_ap_add_maclist() {
	if (rg_pair_info_heap_t == NULL) {
		return;
	}

	struct pair_dev_ath_info *p = rg_pair_info_heap_t;
	char buf[70];

	system(ATH_CMD_CLEAR_MACLIST);
	system(ATH_CMD_ALLOW_MACFILTER);
	while (p) {
		memset(buf,0,sizeof(buf));
		sprintf(buf,ATH_CMD_ADD_MACLIST,p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5]);
		system(buf);
		DEBUG("buf %s",buf);
		p = p->next;
	}
	system("uci commit wireless");
}

//立即生效
void rg_wds_ap_add_maclist_first() {
	if (rg_pair_info_heap_t == NULL) {
		return;
	}

	struct pair_dev_ath_info *p = rg_pair_info_heap_t;
	char buf[70];

	system(ATH_CMD_CLEAR_MACLIST);
	system(ATH_CMD_ALLOW_MACFILTER);
	while (p) {
		memset(buf,0,sizeof(buf));
		sprintf(buf,ATH_CMD_ADD_MACLIST,p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5]);
		system(buf);
		DEBUG("buf %s",buf);
		p = p->next;
	}
	system("uci commit wireless");
}


void rg_wds_ap_clear_maclist() {
	system(ATH_CMD_CLEAR_MACLIST);
	system(ATH_CMD_CLEAR_MACFILTER);
	system("uci commit wireless");
}

void rg_wds_cpe_set_bssid() {

	if (rg_pair_info_heap_t == NULL) {
		return;
	}
	char buf[70];
	memset(buf,0,sizeof(buf));
	sprintf(buf,ATH_SET_CMD_BSSID,
			rg_pair_info_heap_t->mac[0],
			rg_pair_info_heap_t->mac[1],
			rg_pair_info_heap_t->mac[2],
			rg_pair_info_heap_t->mac[3],
			rg_pair_info_heap_t->mac[4],
			rg_pair_info_heap_t->mac[5]);
	DEBUG("buf %s",buf);
	system(buf);
	system("uci commit wireless");
}

void rg_wds_cpe_clear_bssid() {
	DEBUG("");
	system(ATH_CLAER_CMD_BSSID);
	system("uci commit wireless");
}


