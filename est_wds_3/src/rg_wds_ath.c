#include "rg_wds.h"

#define ATH_GET_CMD_MODE       "wireless.%s.ApCliEnable"
#define ATH_GET_CMD_SSID       "wireless.%s.%s"
#define ATH_GET_CMD_BSSID      "uci get wireless.@wifi-iface[0].bssid" //bssid没有适配
#define ATH_SET_CMD_SSID       "uci set wireless.@wifi-iface[0].ssid=%s"
#define ATH_CLAER_CMD_BSSID    "uci delete wireless.@wifi-iface[0].bssid"
#define ATH_GET_CMD_MACLIST       "uci get wireless.@wifi-iface[0].maclist" //没有适配
#define ATH_GET_CMD_MACFILTER     "uci get wireless.@wifi-iface[0].macfilter"

#define ATH_CMD_CLEAR_MACLIST       "uci delete wireless.@wifi-iface[0].maclist"
#define ATH_CMD_ADD_MACLIST         "uci add_list wireless.@wifi-iface[0].maclist=\"%02x:%02x:%02x:%02x:%02x:%02x\""
#define ATH_CMD_CLEAR_MACFILTER     "uci delete wireless.@wifi-iface[0].macfilter"
#define ATH_CMD_ALLOW_MACFILTER     "uci set wireless.@wifi-iface[0].macfilter=\"allow\""

#define ATH_WDS_TYPE_CMD            "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""

#define EST_WIRELESS_UNFITY_FILE    "/etc/rg_config/single/est_wireless_%s.json"

#define EST_WIRELESS_GET_TXPOWER    "uci get wireless.%s.txpower"
#define EST_WIRELESS_GET_DISTANCE    "wireless.%s.distance"

#define DFS_SWITCH "dfs_timeout"

#define CMD_GET_TXPOWER "iwconfig %s|grep Tx-Power|awk -F 'Tx-Power:' '{print $2}'|awk -F ' ' '{print $1}'"
#define CMD_RADER_DETECT_SWITCH    "iwpriv %s set RadarDetectMode=%s"
#define CMD_DFS_NOP_CLEAN    "iwpriv %s set DfsNOPClean=0"
#define FILE_RADER_SWITCH_FLAG "/tmp/rader_switch_flag"

int dfs_uci_switch_status(char *status)
{
    char uci_dfs_switch[5];
    char cactime_cmd[100];
    GPIO_DEBUG("status:%s", status);
    if (strlen(status) == 0) {
        GPIO_ERROR("dfs \"status\" is NULL");
        return FAIL;
    }
    
    memset(uci_dfs_switch, 0, sizeof(uci_dfs_switch));
    read_uci( WIRELESS_UCI_CONFIG_FILE, rg_dev_capacity_table.wifi_name, DFS_SWITCH, uci_dfs_switch);
    
    if (strlen(uci_dfs_switch) == 0) {
        GPIO_DEBUG("read [ wireless.%s.%s fail]", rg_dev_capacity_table.wifi_name, DFS_SWITCH);
    }
    GPIO_DEBUG("compare uci_dfs_switch:%s, status:%s", uci_dfs_switch, status);
    if(strcmp(uci_dfs_switch, status) != 0) {
        if (write_uci("wireless", rg_dev_capacity_table.wifi_name, DFS_SWITCH, status) == AR_FAIL) {
            GPIO_ERROR("write_uci [wireless.%s.%s] fail", rg_dev_capacity_table.wifi_name, DFS_SWITCH);
            return FAIL;
        }
        memset(cactime_cmd, 0, sizeof(cactime_cmd));
        sprintf(cactime_cmd, "iwpriv %s wds_set_nolto %s &", rg_dev_capacity_table.wifi_name, status);
        system(cactime_cmd);
        GPIO_DEBUG("cactime_cmd:%s--", cactime_cmd);
    }
    return SUCESS;
}
int create_file(const char *filename){
	int ret = FAIL;

	if (filename==NULL) {
		return ret;
	}
	
	FILE *pfile = fopen(filename, "w");
	if (pfile!=NULL) {
		fclose(pfile);
		ret = SUCESS;
	}

	return ret;
}
void dfs_switch_control(int connect_stat){
	static int disconnection_time = 0;
    char cmd1[100];
    char cmd2[100];
	if (rg_ath_info_t.role == MODE_CPE) {
		
		if(connect_stat == SUCESS){
			disconnection_time = 0;
			if (access(FILE_RADER_SWITCH_FLAG, F_OK) == FAIL) {
                memset(cmd1, 0, sizeof(cmd1));
                sprintf(cmd1, CMD_RADER_DETECT_SWITCH, rg_dev_capacity_table.wds_ifname, "1");
				system(cmd1);
                
                memset(cmd2, 0, sizeof(cmd2));
                sprintf(cmd2, CMD_DFS_NOP_CLEAN, rg_dev_capacity_table.wds_ifname);
				system(cmd2);

				create_file(FILE_RADER_SWITCH_FLAG);
				GPIO_DEBUG("CPE off DFS");
			}
		} else {
			disconnection_time ++;
			if (access(FILE_RADER_SWITCH_FLAG, F_OK) == SUCESS) {
				if (disconnection_time >= 6 ){
                    memset(cmd1, 0, sizeof(cmd1));
                    sprintf(cmd1, CMD_RADER_DETECT_SWITCH, rg_dev_capacity_table.wds_ifname, "0");
                    system(cmd1);
					remove(FILE_RADER_SWITCH_FLAG);
					GPIO_DEBUG("CPE on DFS, disconnection_time = %d s", disconnection_time*5);
				}
			}
		}
		
	}	
}

bool is_dfs_file_exist(void)
{
    if (access(DFS_FILE_PATH, F_OK) == FAIL) {
        GPIO_WARNING("[ %s ] files not exist.", DFS_FILE_PATH);
        return FALSE;
    }
    GPIO_DEBUG("[ %s ] files exist.", DFS_FILE_PATH);
    return TRUE;
}

bool is_dfs_json_exist(void)
{
     if (access(DFS_JSON_PATH, F_OK) == FAIL) {
        GPIO_WARNING("(warn)[ %s ] files not exist.", DFS_JSON_PATH);
        return FALSE;
    }
    GPIO_DEBUG("[ %s ] files exist.", DFS_JSON_PATH);
    return TRUE;
}

void get_file_content(char *dir, char *buf, int len)
{
    FILE *dfs_fp;
    dfs_fp=fopen(dir, "r");
    if (dfs_fp == NULL) {
        GPIO_ERROR("open [ %s] fail!", dir);
        return;
    }
    fgets(buf, len-1, dfs_fp);
    fclose(dfs_fp);
}

void get_trigger_dfs_channel_time(void)
{
    char buf[512];
    char tmp[512];

    if ( !is_dfs_json_exist() ) {
        if ( is_dfs_file_exist() ) {
            GPIO_DEBUG("first create dfs_json");
            system("cp /proc/est/dfs_radar /etc/rg_config/dfs_json");
        }
    } else if ( is_dfs_file_exist() ) {
        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));
        get_file_content(DFS_FILE_PATH, buf, sizeof(buf));
        get_file_content(DFS_JSON_PATH, tmp, sizeof(tmp));
        if ( strcmp(buf, tmp) != 0 ) {
            GPIO_DEBUG("cp from dfs_radar to dfs_json");
            system("cp /proc/est/dfs_radar /etc/rg_config/dfs_json");
        }
    }
}

char rg_wds_ath_get_name(struct dev_info *dev_info_t,struct ath_info *ath_info_t)
{
	char wds_name[20];
	memset(wds_name, 0, sizeof(wds_name));
    
	if(MODE_CPE == ath_info_t->role){
		strcpy(wds_name, rg_dev_capacity_table.wds_cpe_ifname);
	}else if ( MODE_AP == ath_info_t->role){
		strcpy(wds_name,rg_dev_capacity_table.wds_ifname);
	}	
    memcpy(ath_info_t->ath_wds_name, wds_name, strlen(wds_name));
    memcpy(ath_info_t->ath_managed_name, rg_dev_capacity_table.mag_ifname, strlen(rg_dev_capacity_table.mag_ifname));
	GPIO_DEBUG("rg_ath_info_t init  ath_wds_name: %s", wds_name);
}

char rg_wds_ath_get_mac(struct ath_info *ath_info_t)
{
	char ret;

	//这个地方需要保证一定是成功获取到MAC地址
	while (1) {
		ret = rg_wds_misc_get_mac(ath_info_t->ath_wds_name,ath_info_t->root_mac_hex);
		if (ret == SUCESS) {
			GPIO_DEBUG("ath get mac success,ath_info_t->root_mac_hex=%02X:%02X:%02X:%02X:%02X:%02X", ath_info_t->root_mac_hex[0],\
				ath_info_t->root_mac_hex[1], ath_info_t->root_mac_hex[2],ath_info_t->root_mac_hex[3],ath_info_t->root_mac_hex[4],\
				ath_info_t->root_mac_hex[5]);
			break;
		}
		GPIO_DEBUG("(error)wds ath get mac fail!!!");
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
	char get_ssid_cmd[50];
	memset(get_ssid_cmd, 0, sizeof(get_ssid_cmd));
	memset(ath_info_t->ssid,0,sizeof(ath_info_t->ssid));
	if (MODE_AP == rg_ath_info_t.role){
		sprintf(get_ssid_cmd, ATH_GET_CMD_SSID, rg_dev_capacity_table.wds_ifname, "ssid");
	}else if(MODE_CPE == rg_ath_info_t.role){
		sprintf(get_ssid_cmd, ATH_GET_CMD_SSID, rg_dev_capacity_table.wifi_name, "ApCliSsid");
	}else{
		GPIO_ERROR("rg_ath_info_t init get ssid fail!!!");
	}
	GPIO_DEBUG("get_ssid_cmd:%s", get_ssid_cmd);
	
	rg_wds_uci_get_param(get_ssid_cmd, ath_info_t->ssid, sizeof(ath_info_t->ssid));
	GPIO_DEBUG("ath_info_t->ssid:%s", ath_info_t->ssid);
}

char rg_wds_wifi_get_txpower(struct ath_info *ath_info_t)
{
    char buf[100];

    memset(buf,0,sizeof(buf));

    sprintf(buf, CMD_GET_TXPOWER, rg_ath_info_t.ath_wds_name);
	GPIO_DEBUG("CMD_GET_TXPOWER:%s", buf);
	memset(ath_info_t->wds_txpower,0,sizeof(ath_info_t->wds_txpower));
	rg_wds_misc_get_uci_option(buf,ath_info_t->wds_txpower,sizeof(ath_info_t->wds_txpower));
}

char rg_wds_wifi_get_distance(struct ath_info *ath_info_t)
{
    char buf[50];
    memset(buf,0,sizeof(buf));

    sprintf(buf,EST_WIRELESS_GET_DISTANCE,rg_dev_capacity_table.wifi_name);//把wifi1修改为MT7663_1取决于把distance字段设置到MT7663_1

	memset(ath_info_t->wds_distance,0,sizeof(ath_info_t->wds_distance));

	rg_wds_uci_get_param(buf, ath_info_t->wds_distance, sizeof(ath_info_t->wds_distance));
	GPIO_DEBUG("ath_info_t->wds_distance:%s", ath_info_t->wds_distance);
}

char rg_wds_ath_get_role(struct ath_info *ath_info_t)
{
	char buf[20], get_mode_cmd[50];
	memset(get_mode_cmd, 0, sizeof(get_mode_cmd));
	memset(buf,0,sizeof(buf));
	sprintf(get_mode_cmd, ATH_GET_CMD_MODE, rg_dev_capacity_table.wifi_name);
	rg_wds_uci_get_param(get_mode_cmd, buf, sizeof(buf));
	if (strcmp(buf,ATH_MODE_STA) == 0) {
		ath_info_t->role = MODE_CPE;
	} else {
		ath_info_t->role = MODE_AP;
	} 
	GPIO_DEBUG("rg_ath_info_t init get_mode_cmd:%s, buf:%s, ath_info_t->role %d", get_mode_cmd, buf, ath_info_t->role);
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
	GPIO_DEBUG("buf %s",buf);
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
	GPIO_DEBUG("buf %s",buf);
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
	GPIO_DEBUG("buf %s",buf);
	switch_mac_char_2_hex(buf,ath_info_t->bssid);
	dump_date(ath_info_t->bssid,6);
}

char rg_wds_update_ath(struct dev_info *dev_info_t, struct ath_info *ath_info_t)
{
    if (dev_info_t == NULL || ath_info_t == NULL) {
        GPIO_DEBUG("dev_info_t or ath_info_t is NULL.");
        return FAIL;
    }

    memset(ath_info_t->ath_wds_name, 0, sizeof(ath_info_t->ath_wds_name));
    memset(ath_info_t->ath_managed_name, 0, sizeof(ath_info_t->ath_managed_name));
    memset(ath_info_t->root_mac_hex, 0, sizeof(ath_info_t->root_mac_hex));

    rg_wds_ath_get_name(dev_info_t, ath_info_t);
    rg_wds_ath_get_mac(ath_info_t);
	rg_wds_ath_get_ssid(ath_info_t);
    rg_wds_ath_get_role(ath_info_t);
	rg_wds_wifi_get_txpower(ath_info_t);
    rg_wds_wifi_get_distance(ath_info_t);
}


char rg_wds_ath_init(struct dev_info *dev_info_t,struct ath_info *ath_info_t)
{
	struct sysinfo info;
	sysinfo(&info);

	memset(ath_info_t,0,sizeof(struct ath_info));
	rg_wds_ath_get_role(ath_info_t);
	rg_wds_ath_get_name(dev_info_t,ath_info_t);
	rg_wds_ath_get_mac(ath_info_t);
	rg_wds_ath_get_ssid(ath_info_t);
	GPIO_DEBUG("init ath_info_t.ssid:%s", ath_info_t->ssid);
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

int rg_wds_ath_reload_wifi()
{
	system("kill -9 `ps | grep wifi | awk '{print $1}'`");
	system("wifi &");
	GPIO_FILE("reload wifi");
	return SUCESS;
}

char rg_wds_unlock_2_lock(struct ath_info *ath_info_t)
{
	return;
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
		GPIO_DEBUG("buf %s",buf);
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
		GPIO_DEBUG("buf %s",buf);
		p = p->next;
	}
	system("uci commit wireless");
}


