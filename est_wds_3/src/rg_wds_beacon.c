#include "rg_wds.h"
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "wds_pw_state.h"

#define BEACON_CHECK_TMIE     30*60   //30分钟之后，客户没有通过lock键，锁定设备，则自动选择一个当前信号最前的
#define BEACON_MIN_JOIN_RSSI  20
#define BEACON_RESULT_FILE  "/tmp/wds_scanner_list.json"
#define BEACON_SCAN_DEV_FILE  "/tmp/wds_scan_dev_list.json"
#define BEACON_SCAN_UPDATE_TIME 2

unsigned char fast_wds_flag = 0;
unsigned char wds_fast_keep_live_flag = 0;

struct wds_scan_dev_netid_t *wds_scan_dev_list_p = NULL;


pthread_mutex_t mtx_scan_dev_list;

struct wds_scan_dev_netid_t *find_scan_dev_node_sn(char * dev_sn){
	struct wds_scan_dev_netid_t *dev_list = wds_scan_dev_list_p;
	if(dev_list == NULL){
		GPIO_DEBUG("wds_scan_dev_list_p is null!!!");
		return NULL;
	}
	while(dev_list!=NULL){
		if(strncmp(dev_list->dev_sn, dev_sn, sizeof(dev_list->dev_sn)-1) == 0){
			return dev_list;
		}
		dev_list = dev_list->next;
	}
	if(dev_list==NULL){
		GPIO_DEBUG("Sn(%s) dosn't exist in linked list wds_scan_dev_list_p.", dev_sn);
		return NULL;
	}
}

struct wds_scan_dev_netid_t *find_scan_dev_node_rssi_min(){
	struct wds_scan_dev_netid_t *dev_list = wds_scan_dev_list_p;
	struct wds_scan_dev_netid_t *rssi_min_node = NULL;
	int rssi_min=1000;

	if(dev_list == NULL){
		GPIO_DEBUG("wds_scan_dev_list_p is null!!!");
		return NULL;
	}
	while(dev_list!=NULL){
		if(dev_list->rssi < rssi_min){
			rssi_min = dev_list->rssi;
			rssi_min_node = dev_list;
		}
		dev_list = dev_list->next;
	}

	if(dev_list==NULL){
		GPIO_DEBUG("%s():Sn(%s) rssi(%d) min.", __func__, rssi_min_node->dev_sn, rssi_min_node->rssi);
		return rssi_min_node;
	}
}

int update_scan_dev_node(struct wds_scan_dev_netid_t *list_des_node, struct wds_beacon_info_s *dev_node){
	struct sysinfo info;
	sysinfo(&info);

	if(dev_node == NULL){
		GPIO_DEBUG("This node is null !!!");
		return -1;
	}
	if(list_des_node == NULL){
		GPIO_DEBUG("List node is null !!!");
		return -1;
	}

	if (dev_node->rssi > list_des_node->rssi) {
		list_des_node->rssi= dev_node->rssi;
	} else {
		if (list_des_node->rssi > 0) {
			list_des_node->rssi--;
		}
	}

	/* update time less than 2 second  not update */
	if(info.uptime - list_des_node->time_update < BEACON_SCAN_UPDATE_TIME ) {
		return;
	}

		/* update time less than 2 second  not update */
	if(info.uptime - list_des_node->time_update < BEACON_SCAN_UPDATE_TIME ) {
		return;
	}

	list_des_node->time_update = info.uptime;

	if(list_des_node->role != dev_node->role){
		list_des_node->role = dev_node->role;
	}
	if(list_des_node->pw_stat != dev_node->expand_info.pw_stat){
		list_des_node->pw_stat = dev_node->expand_info.pw_stat;
	}
	if(list_des_node->dev_nm_stat != dev_node->expand_info.dev_nm_stat){
		list_des_node->dev_nm_stat = dev_node->expand_info.dev_nm_stat;
	}
	if(list_des_node->prj_nm_stat != dev_node->expand_info.prj_nm_stat){
		list_des_node->prj_nm_stat = dev_node->expand_info.prj_nm_stat;
	}
	if(list_des_node->connect_stat != dev_node->wds_connect_status){
		list_des_node->connect_stat = dev_node->wds_connect_status;
	}

	if(strncmp(list_des_node->dev_sn, dev_node->sn, sizeof(list_des_node->dev_sn)-1)!=0){
		memset(list_des_node->dev_sn,0,sizeof(list_des_node->dev_sn));
		strncpy(list_des_node->dev_sn, dev_node->sn, strlen(dev_node->sn));
	}

	if(strncmp(list_des_node->dev_name, dev_node->expand_info.dev_name, sizeof(list_des_node->dev_name)-1) !=0 ){
		memset(list_des_node->dev_name,0,sizeof(list_des_node->dev_name));
		strncpy(list_des_node->dev_name, dev_node->expand_info.dev_name, strlen(dev_node->expand_info.dev_name));
	}
	if(strncmp(list_des_node->prj_name, dev_node->expand_info.prj_name, sizeof(list_des_node->prj_name)-1) !=0 ){
		memset(list_des_node->prj_name,0,sizeof(list_des_node->prj_name));
		strncpy(list_des_node->prj_name, dev_node->expand_info.prj_name, strlen(dev_node->expand_info.prj_name));
	}
	if(strncmp(list_des_node->dev_type, dev_node->expand_info.dev_type, sizeof(list_des_node->dev_type)-1) !=0 ){
		strncpy(list_des_node->dev_type, dev_node->expand_info.dev_type, strlen(dev_node->expand_info.dev_type));
	}
	if(memcmp(list_des_node->dev_mac, dev_node->expand_info.dev_mac, sizeof(list_des_node->dev_mac)) !=0 ){
		memcpy(list_des_node->dev_mac, dev_node->expand_info.dev_mac, sizeof(list_des_node->dev_mac));
	}
	if(memcmp(list_des_node->ath_mac, dev_node->expand_info.ath_mac, sizeof(list_des_node->ath_mac)) !=0 ){
		memcpy(list_des_node->ath_mac, dev_node->expand_info.ath_mac, sizeof(list_des_node->ath_mac));
	}

	DEBUG_ERROR("%s():wds_scan_dev_list_p node sn(%s) update success.", __func__, list_des_node->dev_sn)
	return 0;
}

void init_wds_scan_dev_list(struct wds_beacon_info_s *dev_node){
	if(!dev_node){
		GPIO_DEBUG("%s():Init list fail, dev_node is null !!!", __func__);
	}

	if(wds_scan_dev_list_p == NULL){
		wds_scan_dev_list_p= (struct wds_scan_dev_netid_t *)malloc(sizeof(struct wds_scan_dev_netid_t));
		if(wds_scan_dev_list_p == NULL){
			GPIO_DEBUG("%s():init node(sn:%s) fail, malloc fail !!!", __func__, dev_node->sn);
			return;
		}
		memset(wds_scan_dev_list_p, 0, sizeof(struct wds_scan_dev_netid_t));
	}

	update_scan_dev_node(wds_scan_dev_list_p, dev_node);

	GPIO_DEBUG("%s() Init success", __func__);
	return;
}

int get_wds_scan_dev_list_len(){
	struct wds_scan_dev_netid_t *dev_list = wds_scan_dev_list_p;
	int len=0;

	while(dev_list!=NULL){
		len++;
		dev_list = dev_list->next;
	}

	return len;
}

int add_scan_dev_node(struct wds_beacon_info_s *dev_node){
	struct wds_scan_dev_netid_t *dev_list = wds_scan_dev_list_p;
	struct wds_scan_dev_netid_t *dev_list_last = NULL;
	struct wds_scan_dev_netid_t *dev_rssi_min = NULL;

	if(wds_scan_dev_list_p == NULL){
		init_wds_scan_dev_list(dev_node);
		return 0;
	}

	if(get_wds_scan_dev_list_len() >= SCAN_DEV_LIST_MAX_LENGTH){
		dev_rssi_min = find_scan_dev_node_rssi_min();
		if(!dev_rssi_min){
			GPIO_DEBUG("%s():Node with min rssi not found", __func__);
			return -1;
		}
		update_scan_dev_node(dev_rssi_min, dev_node);
		GPIO_DEBUG("%s():The min rssi node(sn:%s) has been updated", __func__, dev_rssi_min->dev_sn);
		return 0;
	}

	while(dev_list != NULL){
		dev_list_last = dev_list;
		dev_list = dev_list->next;
	}

	if(dev_list == NULL){
		dev_list = (struct wds_scan_dev_netid_t *)malloc(sizeof(struct wds_scan_dev_netid_t));
		if(dev_list == NULL){
			GPIO_DEBUG("add node(sn:%s) fail, malloc fail !!!", dev_node->sn);
			return -1;
		}
		memset(dev_list, 0, sizeof(struct wds_scan_dev_netid_t));

		dev_list_last->next = dev_list;
	}

	update_scan_dev_node(dev_list,  dev_node);
	GPIO_DEBUG("add node(sn:%s) success", dev_node->sn);
	return 0;

}

void delete_overtime_scan_dev_node(){
	struct wds_scan_dev_netid_t *dev_list = wds_scan_dev_list_p;
	struct wds_scan_dev_netid_t *overtime_node_pre = NULL;
	int delete_num = 0;
	struct sysinfo info;

	if(!dev_list){
		GPIO_DEBUG("%s():The wds_scan_dev_list_p==NULL", __func__);
		return;
	}

	sysinfo(&info);

	while(dev_list){
		if(info.uptime - dev_list->time_update > SCANDEV_LIST_UPTIME){
			delete_num++;
			GPIO_DEBUG("%s():rm overtime sn(%s) in wds_scan_dev_list_p.", __func__, dev_list->dev_sn);
			if(dev_list==wds_scan_dev_list_p){
				wds_scan_dev_list_p = dev_list->next;
				free(dev_list);
				dev_list =NULL;
				overtime_node_pre = NULL;
				dev_list = wds_scan_dev_list_p;
			}else{
				overtime_node_pre->next = dev_list->next;
				free(dev_list);
				dev_list =NULL;
				dev_list = overtime_node_pre->next;
			}

			continue;
		}

		overtime_node_pre = dev_list;
		dev_list = dev_list->next;
	}

	if(delete_num){
		GPIO_DEBUG("%s():Delete %d overtime timeout devices in wds_scan_dev_list_p.", __func__, delete_num);
	}

}

/*AP provides scanning device information to the interface(dev_sta get --module 'scanWdsDevice')*/
char scan_dev_list_to_file() {

	struct wds_scan_dev_netid_t *dev_list = wds_scan_dev_list_p;
	char buf[20];
	int tmp_stat=-1;

	json_object *file = json_object_new_object();
	json_object *arr = json_object_new_array();

	if (rg_ath_info_t.role == MODE_CPE) {
		/*AP切换为CPE时不再写原AP扫描设备链表里的信息到json({"LIST":[]})，链表里的超时设备会自己删除(delete_overtime_scan_dev_node())*/
		/*When switching from AP to CPE,
		*the information in the original AP scanning device list will no longer be written to JSON({"LIST":[]}),
		*and the timeout devices in the list will be deleted on their own(delete_overtime_scan_dev_node())*/
		GPIO_DEBUG("CPE does not provide scanning device information");
		goto wirte_json;
	}

	pthread_mutex_lock(&mtx_scan_dev_list);

	while (dev_list != NULL) {
		json_object *item = json_object_new_object();

		if(ROLE_AP == dev_list->role){
			json_object_object_add(item, "role", json_object_new_string("ap"));
		}else if(ROLE_CPE == dev_list->role){
			json_object_object_add(item, "role", json_object_new_string("cpe"));
		}
		json_object_object_add(item, "devType", json_object_new_string(dev_list->dev_type));
		json_object_object_add(item, "sn", json_object_new_string(dev_list->dev_sn));
		memset(buf,0,sizeof(buf));
		sprintf(buf,MAC2STR,PRINT_MAC(dev_list->dev_mac));
		json_object_object_add(item, "devMac", json_object_new_string(buf));
		memset(buf,0,sizeof(buf));
		sprintf(buf,MAC2STR,PRINT_MAC(dev_list->ath_mac));
		json_object_object_add(item, "athMac", json_object_new_string(buf));
		memset(buf,0,sizeof(buf));
		sprintf(buf,"%d",dev_list->pw_stat);
		json_object_object_add(item, "pwStat", json_object_new_string(buf));
		json_object_object_add(item, "devName", json_object_new_string(dev_list->dev_name));
		memset(buf,0,sizeof(buf));
		if(dev_list->dev_nm_stat == 1){
			tmp_stat = 0;
		}else{
			tmp_stat = 1;
		}
		sprintf(buf,"%d",tmp_stat);
		json_object_object_add(item, "devNmStat", json_object_new_string(buf));
		json_object_object_add(item, "projectName", json_object_new_string(dev_list->prj_name));
		memset(buf,0,sizeof(buf));
		tmp_stat=-1;
        if(dev_list->prj_nm_stat == 1){
			tmp_stat = 0;
		}else{
			tmp_stat = 1;
		}
		sprintf(buf,"%d",tmp_stat);
		json_object_object_add(item, "prjNmStat", json_object_new_string(buf));
        if (dev_list->rssi > 0) {
			memset(buf,0,sizeof(buf));
            sprintf(buf,"%d",dev_list->rssi - 95);
        }
		json_object_object_add(item, "rssi", json_object_new_string(buf));

		json_object_array_add(arr, item);

		dev_list = dev_list->next;
	}
	pthread_mutex_unlock(&mtx_scan_dev_list);

wirte_json:
	json_object_object_add(file, "LIST", arr);

	const char *str = json_object_to_json_string(file);

	int fd;
	/* 打开一个文件 */
	fd = open(BEACON_SCAN_DEV_FILE,O_RDWR);
	if(fd < 0)
	{
		GPIO_ERROR("open file[%s] failed", BEACON_SCAN_DEV_FILE);
	}
	else
	{
		/* 清空文件 */
		ftruncate(fd,0);
		/* 重新设置文件偏移量 */
		lseek(fd,0,SEEK_SET);
		close(fd);
	}

	fd = open(BEACON_SCAN_DEV_FILE, O_CREAT | O_RDWR,0644);
	write(fd,str,strlen(str));
	close(fd);
	json_object_put(file);
}

/*AP receives scanned device information*/
void rg_wds_beacon_expand_process(struct wds_beacon_info_s *beacon_p){
	struct wds_scan_dev_netid_t * dev_list_node = NULL;

	if(!beacon_p){
		GPIO_DEBUG("beacon_p is null");
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		return;
	}
//	printf("---------------------------------------------------------\n");
//	GPIO_DEBUG("%s():recev kernel scandev is_exist_expend=%d, info beacon_p->sn=%s, role=%d, wds_connect_status=%d, rssi=%d, wds_ssid=%s", __func__, beacon_p->is_exist_expend, beacon_p->sn, beacon_p->role, beacon_p->wds_connect_status, beacon_p->rssi, beacon_p->wds_ssid);
//	GPIO_DEBUG("%s():this_athmac="MAC2STR", dev_type=%s, dev_mac="MAC2STR", ath_mac="MAC2STR", dev_name=%s, prj_name=%s, dev_nm_stat=%d prj_nm_stat=%d pw_stat=%d", __func__, PRINT_MAC(beacon_p->mac), beacon_p->expand_info.dev_type, PRINT_MAC(beacon_p->expand_info.dev_mac), PRINT_MAC(beacon_p->expand_info.ath_mac), beacon_p->expand_info.dev_name, beacon_p->expand_info.prj_name, beacon_p->expand_info.dev_nm_stat, beacon_p->expand_info.prj_nm_stat, beacon_p->expand_info.pw_stat);
//	printf("---------------------------------------------------------\n");
	dev_list_node = find_scan_dev_node_sn(beacon_p->sn);
	if(dev_list_node != NULL){
		GPIO_DEBUG("Node(%s) found, update ", dev_list_node->dev_sn);
		update_scan_dev_node(dev_list_node, beacon_p);
	}else{
		add_scan_dev_node(beacon_p);
	}
}


/*The switch for broadcasting device information.
 *1.The AP turns off broadcasting its own information,
 *2.The CPE bridge disconnects and opens the broadcasting device information.
 *  After the bridge is connected, the broadcasting device information is turned off.
 */

void bcn_expand_info_switch(int connet_stat){
	char bcn_switch_stat_cmd[50];
	char bcn_switch_stat_value[4];

    memset(bcn_switch_stat_cmd, 0, sizeof(bcn_switch_stat_cmd));
    memset(bcn_switch_stat_value, 0, sizeof(bcn_switch_stat_value));

    /*获取到BcnExpendSwitch的值*/
    snprintf(bcn_switch_stat_cmd, sizeof(bcn_switch_stat_cmd), CMD_GET_WDS_DF_PW, rg_dev_capacity_table.wifi_name,"BcnExpendSwitch");
    GPIO_DEBUG("%s() bcn_switch_stat_cmd=%s", __func__, bcn_switch_stat_cmd);
    rg_wds_uci_get_param(bcn_switch_stat_cmd, bcn_switch_stat_value,sizeof(bcn_switch_stat_value));

    GPIO_DEBUG("%s() bcn_switch_stat_value=%s",__func__, bcn_switch_stat_value);

		if(rg_ath_info_t.role == MODE_AP){
		if (strncmp(bcn_switch_stat_value, "1", 1) == 0) {
            GPIO_DEBUG("%s() This AP, close beacon switch", __func__);
            if (write_uci("wireless", rg_dev_capacity_table.wifi_name, "BcnExpendSwitch", "0") == AR_FAIL) {
                GPIO_DEBUG("%s() AP wirte_uci BcnExpendSwitch is err", __func__);
                return;
            }
            system("wifi reload");
		}
		return;
	}

	if(connet_stat == SUCESS){
        GPIO_DEBUG("%s() connect success", __func__);
		if( strncmp(bcn_switch_stat_value, "1", 1) == 0){
            GPIO_DEBUG("%s() close beacon switch", __func__);
            if(write_uci("wireless", rg_dev_capacity_table.wifi_name, "BcnExpendSwitch", "0") == AR_FAIL){
                GPIO_DEBUG("%s() wirte_uci BcnExpendSwitch is err", __func__);
                return;
            }
            system("wifi reload");
		}
	}else{
        GPIO_DEBUG("%s() connect not sucess", __func__);
		if( strncmp(bcn_switch_stat_value, "0", 1) == 0){
            GPIO_DEBUG("%s() open beacon switch", __func__);
            if(write_uci("wireless", rg_dev_capacity_table.wifi_name, "BcnExpendSwitch", "1") == AR_FAIL){
                GPIO_DEBUG("%s() wirte_uci BcnExpendSwitch is err", __func__);
                return;
            }
            system("wifi reload");
		}
    }
}


int read_network_json_hostname(char * config_file, char * netwrok_nm, int netnm_size, int *nm_stat ){
	struct json_object *file_json = NULL, *json1 = NULL;
	int resout = FAIL;
	int length;
	char * file_data = NULL;
	char *dev_namework_nm = NULL;

	if(!config_file||!netwrok_nm){
		GPIO_DEBUG("err, config_file=NULL or ntwork_nm=NULL");
		goto net_end;
	}

	file_data = ReadFile(config_file, &length);
	if(NULL == file_data){
        GPIO_ERROR("(err)Open file[%s] fail!", config_file);
        goto net_end;
    }
	file_json = json_tokener_parse((const char *)file_data);

    if (!file_json) {
        GPIO_ERROR("(err)Fail to get network cfg json string!");
        goto net_end;
    }
	json1 = json_object_object_get(file_json, "networkName");
    if (!json1) {
        GPIO_ERROR("networkName is NULL!");
        goto net_end;
    }

	dev_namework_nm = json_object_get_string(json1);
	if (!dev_namework_nm) {
        GPIO_ERROR("dev_namework_nm is NULL!");
        goto net_end;
    }

	if(strlen(dev_namework_nm) >= netnm_size){
		*nm_stat = 1;
	}else{
		*nm_stat = 0;
	}
	strncpy(netwrok_nm, dev_namework_nm, netnm_size-1);
	resout = SUCESS;

net_end:
	if(file_json){
        json_object_put(file_json);
    }
	if(file_data){
		free(file_data);
	}
	return resout;
}

//iwpriv rax set bcn_est_expend_info=ath_mac%dev_name%dev_nm_stat%prj_name%prj_nm_stat%pw_stat
char str_last[IW_CMD_LEN]={0};
void update_beacon_info(){

	if(rg_ath_info_t.role == MODE_AP){
		return;
	}

	//38+17+65+1+65+1+1+5+1
	char str[IW_CMD_LEN];
	char str2[68];
	char str3[50];
	int stat;

	memset(str, 0, sizeof(str));

	//iwpriv
	sprintf(str,UPDATE_BCN_IW,rg_dev_capacity_table.wds_ifname);

	//athmac
	memset(str2, 0, sizeof(str2));
	sprintf(str2, MAC2STR, PRINT_MAC(rg_ath_info_t.root_mac_hex));
	if(strlen(str2)==0){
		GPIO_DEBUG("get ath_mac fail!!!");
		return;
	}
	strcat(str, str2);
	strcat(str, "%");

	//dev_name
	memset(str2, 0, sizeof(str2));
	strncpy(str2, rg_dev_info_t.host_name, DEV_NAME_LEN-1);
	if(strlen(str2)==0){
		GPIO_DEBUG("get dev_name fail!!!");
		return;
	}
	strcat(str, str2);
	strcat(str, "%");

	//dev_nm_stat
	if(strlen(rg_dev_info_t.host_name)>=DEV_NAME_LEN){
		strcat(str, "1");//1 represents incomplete name display
	}else{
		strcat(str, "0");//0 represents full display of name
	}
	strcat(str, "%");

	//prj_name
	if (access(CONFIG_NETWORKID, F_OK) == FAIL) {
        GPIO_WARNING("(warn)[ %s ] files not exist.", DFS_JSON_PATH);
        strcat(str, "default");
		strcat(str, "%");
		strcat(str, "0");//0 represents full display of name
    }else{
		memset(str2, 0, sizeof(str2));
		if(read_network_json_hostname(CONFIG_NETWORKID, str2, PRJ_NAME_LEN, &stat)==FAIL){
			GPIO_DEBUG("get prj_name fail!!!");
			return;
		}
		strcat(str, str2);
		strcat(str, "%");
		if(stat==1){
			strcat(str, "1");//1 represents incomplete name display
		}else{
			strcat(str, "0");//0 represents full display of name
		}
	}
	strcat(str, "%");


	//pw_stat
	memset(str3, 0, sizeof(str3));
	memset(str2, 0, sizeof(str2));


	sprintf(str3, CMD_GET_WDS_DF_PW, rg_dev_capacity_table.wifi_name, "ApCliWPAPSK");
	GPIO_DEBUG("%s() get_uci_wds_pw_cmd str3:%s", __func__, str3);


	rg_wds_uci_get_param(str3, str2, sizeof(str2));
#if 1

	GPIO_DEBUG("%s() uci_wds_pw str2:%s", __func__, str2);


	if(strlen(str2)==0||strlen(str3)==0){
		GPIO_DEBUG("get wds pw fail!!!");
		return;
	}

	if(strcmp(str2, WDS_DF_PW) == 0){
		strcat(str, "0"); //0 means it is the default password
	}else {
		strcat(str, "1");//1 means it is not the default password
	}


	GPIO_DEBUG("Beacon str=%s str_last=%s", str, str_last);
	if(strcmp(str, str_last)!=0){
		GPIO_DEBUG("UPDATE Beacon %s", str);
		system(str);
		memset(str_last, 0, sizeof(str_last));
		strcpy(str_last, str);
	}else{
		GPIO_DEBUG("Beacon dosn't need to be updated");
	}
#endif

	GPIO_DEBUG("%s end", __func__);
	return;
}

int nl_fd;
struct sockaddr_nl nl_address;
int nl_family_id;
struct nlattr *nl_na;
struct { //
    struct nlmsghdr n;
    struct genlmsghdr g;
    char buf[256];
} nl_request_msg, nl_response_msg, nl_wdspw_msg;

void rg_wds_beacon_show() {
	struct wds_ssid_netid_t *p;
	p = wds_ssid_list_p;
	int i = 0;

	GPIO_DEBUG("--------------------------------   begin  -----------------------------------");
	while (p != NULL) {
		GPIO_DEBUG("i %d",i);
		GPIO_DEBUG("role_ap %d",p->role_ap);
		GPIO_DEBUG("role_cpe %d",p->role_cpe);
		GPIO_DEBUG("rssi_ap %d",p->rssi_ap);
		GPIO_DEBUG("rssi_cpe %d",p->rssi_cpe);
		GPIO_DEBUG("time_update_ap %d",p->time_update_ap);
		GPIO_DEBUG("time_update_cpe %d",p->time_update_cpe);
		GPIO_DEBUG("wds_connect_status_cpe %d",p->wds_connect_status_cpe);
		GPIO_DEBUG("cpe rssi_max_count %d",p->rssi_max_count);
		GPIO_DEBUG("wds_ssid %s",p->wds_ssid);
		dump_date(p->mac,sizeof(p->mac));
		p = p->next;
		i++;
	}
	GPIO_DEBUG("---------------------------    end   ----------------------------------------");
}

char wds_list_length() {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	char len = 0;

	while (p != NULL) {
		len++;
		p = p->next;
	}

	return len;
}


//更新已经存在的节点的信息,更新部分数据
void wds_list_update(struct wds_beacon_info_s *beacon_p,struct wds_ssid_netid_t *wds_list_p) {
	struct sysinfo info;

	//获取当前时间
	sysinfo(&info);

	if (beacon_p->role == ROLE_AP) {
		//接受的AP的信号强度，以当前的为准
		//wds_list_p->rssi_ap = beacon_p->rssi;
        //减小信号波动
        if (beacon_p->rssi > wds_list_p->rssi_ap) {
            wds_list_p->rssi_ap = beacon_p->rssi;
        } else {
            if (wds_list_p->rssi_ap > 0) {
                wds_list_p->rssi_ap--;
            }
        }

		wds_list_p->role_ap = 1;
		wds_list_p->time_update_ap = info.uptime;
        /* ap sn信息存储 */
        memset(wds_list_p->ap_sn, 0, sizeof(wds_list_p->ap_sn));
        strncpy(wds_list_p->ap_sn, beacon_p->sn, sizeof(wds_list_p->ap_sn) - 1);
	} else if (beacon_p->role == ROLE_CPE) {
		//接受的CPE的信号强度，以当前的地表最强战队为准，因为有可能存在多个CPE的情况，所以只能以最强的为准
		wds_list_p->role_cpe= 1;
		//信号强度以最大为限度
		if (beacon_p->rssi >= wds_list_p->rssi_cpe) {
			wds_list_p->rssi_cpe = beacon_p->rssi;
			memcpy(wds_list_p->mac,beacon_p->mac,sizeof(wds_list_p->mac));
			wds_list_p->time_update_cpe = info.uptime;
			wds_list_p->wds_connect_status_cpe = beacon_p->wds_connect_status;
		} else {
            //每次减小1，等待最高的那个信号重新更新，这样可以保持rssi数据是最新的
			wds_list_p->time_update_cpe = info.uptime;
			wds_list_p->wds_connect_status_cpe = beacon_p->wds_connect_status;
            if (wds_list_p->rssi_cpe > 0) {
                wds_list_p->rssi_cpe--;
            }
		}
        /* cpe sn信息存储 */
        memset(wds_list_p->cpe_sn, 0, sizeof(wds_list_p->cpe_sn));
        strncpy(wds_list_p->cpe_sn, beacon_p->sn, sizeof(wds_list_p->cpe_sn) - 1);
	}
}

//更新已经存在的节点的信息	，全部更新
void wds_list_update_all(struct wds_beacon_info_s *beacon_p,struct wds_ssid_netid_t *wds_list_p) {
	struct sysinfo info;

	//获取当前时间
	sysinfo(&info);

	//SSID拷贝
	memcpy(wds_list_p->wds_ssid,beacon_p->wds_ssid,sizeof(wds_list_p->wds_ssid));
	if (beacon_p->role == ROLE_AP) {
		//接受的AP的信号强度，以当前的为准

		wds_list_p->rssi_ap = beacon_p->rssi;
		wds_list_p->role_ap = 1;
		wds_list_p->time_update_ap = info.uptime;
        /* ap sn信息存储 */
        memset(wds_list_p->ap_sn, 0, sizeof(wds_list_p->ap_sn));
        strncpy(wds_list_p->ap_sn, beacon_p->sn, sizeof(wds_list_p->ap_sn) - 1);
	} else if (beacon_p->role == ROLE_CPE) {
		//接受的CPE的信号强度，以当前的地表最强战队为准，因为有可能存在多个CPE的情况，所以只能以最强的为准
        wds_list_p->role_cpe = 1;
		wds_list_p->rssi_cpe = beacon_p->rssi;
		wds_list_p->time_update_cpe = info.uptime;
		memcpy(wds_list_p->mac,beacon_p->mac,sizeof(beacon_p->mac));
		wds_list_p->wds_connect_status_cpe = beacon_p->wds_connect_status;
        /* cpe sn信息存储 */
        memset(wds_list_p->cpe_sn, 0, sizeof(wds_list_p->cpe_sn));
        strncpy(wds_list_p->cpe_sn, beacon_p->sn, sizeof(wds_list_p->cpe_sn) - 1);
	}
}

//找出RSSI最小的节点
struct wds_ssid_netid_t * wds_list_find_min_rssi() {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	struct wds_ssid_netid_t *p_dst;
	p_dst = NULL;
	char len = 0;

	int rssi = 10000;
	int rssi_tmp = 0;

	while (p != NULL) {
		//比对的时候，要比当前CPE和AP的都要大
		if (p->rssi_ap >= p->rssi_cpe) {
			rssi_tmp = p->rssi_ap;
		} else {
			rssi_tmp = p->rssi_cpe;
		}

		if (rssi_tmp < rssi) {
			rssi = rssi_tmp;
			p_dst = p;
		}
		len++;
		p = p->next;
	}

	return p_dst;
}

char wds_list_rssi_compare(struct wds_ssid_netid_t *p,int rssi) {
	int rssi_tmp = 0;
	char ret = 0;

	if (p->rssi_ap >= p->rssi_cpe) {
		rssi_tmp = p->rssi_ap;
	} else {
		rssi_tmp = p->rssi_cpe;
	}

	if (rssi >= rssi_tmp) {
		if (rssi - rssi_tmp >= WDS_LIST_RSSI_COMPARE) {
			ret = 1;
		}
	}

	return ret;
}

//找出RSSI最大的节点
struct wds_ssid_netid_t * wds_list_find_max_rssi(char role) {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	struct wds_ssid_netid_t *p_dst = NULL;

	int rssi = 0;
	int rssi_tmp = 0;

	while (p != NULL) {
		if (p->role_ap == 1 && role == MODE_CPE) {
			//找到当前有AP存在的网络的非默认SSID的网络
			//比对的时候，要比当前CPE和AP的都要大
			if (p->rssi_ap >= p->rssi_cpe) {
				rssi_tmp = p->rssi_ap;
			} else {
				rssi_tmp = p->rssi_cpe;
			}

			//DEBUG("rssi_tmp %d rssi %d",rssi_tmp,rssi);
			if (rssi_tmp > rssi) {
				rssi = rssi_tmp;
				p_dst = p;
			}
		} else if (p->role_ap == 0 && p->role_cpe == 1 && role == MODE_AP) {
			//AP加入的网络，一定是不能已经有AP存在的，至少当前不能看到AP的存在，如果只是下电了，那这边是没有办法检测出来的
			//比对的时候，要比当前CPE和AP的都要大
			if (p->rssi_ap >= p->rssi_cpe) {
				rssi_tmp = p->rssi_ap;
			} else {
				rssi_tmp = p->rssi_cpe;
			}

			//DEBUG("rssi_tmp %d rssi %d",rssi_tmp,rssi);
			if (rssi_tmp > rssi) {
				rssi = rssi_tmp;
				p_dst = p;
			}
		}
		p = p->next;
	}

	return p_dst;
}

//添加节点的信息
void wds_list_add(struct wds_beacon_info_s *beacon_p,struct wds_ssid_netid_t *wds_list_p) {
	char len;
	struct wds_ssid_netid_t *p;
	int rssi = 0;

	len = wds_list_length();

	//链表小于16个的时候，直接添加就可以，超过的话，就比对最弱的那个，如果小的话，就直接删除，然后再删除
	if (len < WDS_LIST_MAX_LENGTH) {
		p = (struct wds_ssid_netid_t *)malloc(sizeof(struct wds_ssid_netid_t));
		if (p == NULL) {
			GPIO_DEBUG("malloc error");
			return;
		}
        memset(p,0,sizeof(struct wds_ssid_netid_t));
		wds_list_update_all(beacon_p,p);
		if (wds_list_p == NULL) {
			wds_ssid_list_p = p;
		} else {
			wds_list_p->next = p;
		}
	} else {
		p = wds_list_find_min_rssi();
		if (p->rssi_ap >= p->rssi_cpe) {
			rssi = p->rssi_ap;
		} else {
			rssi = p->rssi_cpe;
		}

		//DEBUG("rssi %d beacon_p->rssi %d",rssi,beacon_p->rssi);
		//信号有差距，并且在一定的范围内，测试更新该节点
		if (beacon_p->rssi - rssi >= RSSI_DELETE) {
			wds_list_update_all(beacon_p,p);
			GPIO_DEBUG("rssi %d beacon_p->rssi %d",rssi,beacon_p->rssi);
		}
	}
}

void wds_list_clear(struct wds_ssid_netid_t *p) {
	p->rssi_ap = 0;
	p->rssi_cpe = 0;
	p->role_ap = 0;
	p->role_cpe = 0;
	p->rssi_max_count = 0;
	p->time_update_ap = 0;
	p->time_update_cpe = 0;
	p->wds_connect_status_cpe = 0;
	memset(p->wds_ssid,0,sizeof(p->wds_ssid));
	memset(p->mac,0,sizeof(p->mac));
    memset(p->ap_sn, 0, sizeof(p->ap_sn));
    memset(p->cpe_sn, 0, sizeof(p->cpe_sn));
}
void wds_list_time_update() {
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	struct sysinfo info;
	char len = 0;

	//获取当前时间
	sysinfo(&info);

	//仅仅更新为0，不删除，可能会被替换
	while (p != NULL) {
		if ((p->time_update_ap > 0 || p->time_update_cpe > 0) && info.uptime - p->time_update_ap >= WDS_LIST_UPTIME && info.uptime - p->time_update_cpe >= WDS_LIST_UPTIME) {
			GPIO_DEBUG("len %d info.uptime %d p->time_update_ap",len,info.uptime,p->time_update_ap);
			wds_list_clear(p);
		}
		len++;
		p = p->next;
	}
}

char rg_wds_list_scanner() {

	pthread_mutex_lock(&mtx_wds_beacon_list);
	struct wds_ssid_netid_t *p = wds_ssid_list_p;
	char buf[20];

	json_object *file = json_object_new_object();
	json_object *section = json_object_new_array();

	while (p != NULL) {
		if (strlen(p->wds_ssid) != 0) {
            //AP直接过滤 有AP的wds
//            if (rg_ath_info_t.role == MODE_AP) {
//                if (p->role_ap == 1) {
//                    goto loop;
//                }
//            }
			json_object *item = json_object_new_object();
			json_object_object_add(item, "ssid", json_object_new_string(p->wds_ssid));

			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->role_ap);
			json_object_object_add(item, "ap", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
            if (p->rssi_ap > 0) {
                sprintf(buf,"%d",p->rssi_ap - 95);
            }
			json_object_object_add(item, "ap_rssi", json_object_new_string(buf));

			memset(buf, 0, sizeof(buf));
            if (strlen(p->ap_sn)) {
                sprintf(buf, "%s", p->ap_sn);
            }
            json_object_object_add(item, "ap_peer_sn", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
			sprintf(buf,"%d",p->role_cpe);
			json_object_object_add(item, "cpe", json_object_new_string(buf));

			memset(buf,0,sizeof(buf));
            if (p->rssi_cpe > 0) {
                sprintf(buf,"%d",p->rssi_cpe - 95);
            }
			json_object_object_add(item, "cpe_rssi", json_object_new_string(buf));

			memset(buf, 0, sizeof(buf));
            if (strlen(p->cpe_sn)) {
                sprintf(buf, "%s", p->cpe_sn);
            }
            json_object_object_add(item, "cpe_peer_sn", json_object_new_string(buf));

			json_object_array_add(section, item);
		}
loop:
		p = p->next;
	}
	pthread_mutex_unlock(&mtx_wds_beacon_list);
	json_object_object_add(file, "LIST", section);

	const char *str = json_object_to_json_string(file);

	int fd;
	/* 打开一个文件 */
	fd = open(BEACON_RESULT_FILE,O_RDWR);
	if(fd < 0)
	{
		GPIO_ERROR("open file[%s] failed", BEACON_RESULT_FILE);
	}
	else
	{
		/* 清空文件 */
		ftruncate(fd,0);
		/* 重新设置文件偏移量 */
		lseek(fd,0,SEEK_SET);
		close(fd);
	}

	fd = open(BEACON_RESULT_FILE, O_CREAT | O_RDWR,0644);
	write(fd,str,strlen(str));
	close(fd);
	json_object_put(file);
}

void rg_wds_beacon_process(struct wds_beacon_info_s *beacon_p) {
	struct wds_ssid_netid_t *p;
	struct wds_ssid_netid_t *p_last;
	char len = 0;

	if (strlen(beacon_p->wds_ssid) == 0 || beacon_p->rssi-95 == 0 || (beacon_p->role != ROLE_AP && beacon_p->role != ROLE_CPE)) {
		GPIO_DEBUG("beacon error");
		return;
	}

	len = wds_list_length();

	p = wds_ssid_list_p;
	p_last = p;
	while (p != NULL) {
		//找到这个网络ID
		if (memcmp(p->wds_ssid,beacon_p->wds_ssid,sizeof(p->wds_ssid)) == 0) {
			//DEBUG("beacon_p->wds_ssid %s",beacon_p->wds_ssid);
			wds_list_update(beacon_p,p);
			break;
		}
		p_last = p;
		p = p->next;
	}

	if (p == NULL && wds_ssid_list_p == NULL) {
		//一个都没有找到,且一个都没有
		wds_list_add(beacon_p,wds_ssid_list_p);
	} else if(p == NULL) {
		//给下一个赋值
		wds_list_add(beacon_p,p_last);
	}
}


void reset_oneclick_and_scanpair(void){
	pthread_mutex_lock(&wds_fast_pair_mtx);
	if (fast_wds_flag == 1) {
	    fast_wds_flag = 0;
		wds_fast_keep_live_flag = 0;
	} else {
	    pthread_mutex_unlock(&wds_fast_pair_mtx);
	    return;
	}
	pthread_mutex_unlock(&wds_fast_pair_mtx);
	char cmd[128] = { 0 };
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "led_send_message \"mesh;default\"");
	GPIO_FILE("cmd : %s\n", cmd);
	system(cmd);
}

void rg_wds_ssid_and_key(unsigned char *driv_ssid,unsigned char *driv_key)
{
	char ssid[MAX_LEN_OF_SSID+1];
	char get_uci_wds_ssid_key_cmd[50];
	char set_ssid_cmd[MAX_LEN_OF_SSID+25+1];
	char cmd[128]={0};


	memset(ssid, 0, sizeof(ssid));
	memset(get_uci_wds_ssid_key_cmd, 0, sizeof(get_uci_wds_ssid_key_cmd));

	snprintf(get_uci_wds_ssid_key_cmd, 50, CMD_GET_UCI_WDS_FMT, rg_dev_capacity_table.wifi_name, "ApCliSsid");	/* uci get wireless.MT7628_1.ApCliSsid */
	rg_wds_uci_get_param(get_uci_wds_ssid_key_cmd, ssid, sizeof(ssid));

	if(strncmp(ssid, driv_ssid, sizeof(ssid))!=0){
		memset(ssid, 0, sizeof(ssid));
		strncpy(ssid, driv_ssid, sizeof(ssid));

		memset(set_ssid_cmd, 0, sizeof(set_ssid_cmd));
		sprintf(set_ssid_cmd, "wds_config_ssid_key ssid %s", ssid);
		GPIO_DEBUG("%s", set_ssid_cmd);
		system(set_ssid_cmd);
	}

	char key[LEN_PSK+1];
	char set_key_cmd[LEN_PSK+25+1];

	memset(key, 0, sizeof(key));
	memset(get_uci_wds_ssid_key_cmd, 0, sizeof(get_uci_wds_ssid_key_cmd));

	snprintf(get_uci_wds_ssid_key_cmd, 50, CMD_GET_UCI_WDS_FMT, rg_dev_capacity_table.wifi_name, "ApCliWPAPSK"); /* uci get wireless.MT7628_1.ApCliWPAPSK */
	rg_wds_uci_get_param(get_uci_wds_ssid_key_cmd, key, sizeof(key));

	if(strncmp(key, driv_key, sizeof(key))!=0){
		memset(key, 0, sizeof(key));
		strncpy(key, driv_key, sizeof(key));

		memset(set_key_cmd, 0, sizeof(set_key_cmd));
		sprintf(set_key_cmd, "wds_config_ssid_key key %s", key);
		GPIO_DEBUG("%s", set_key_cmd);
		system(set_key_cmd);
	}
	memset(cmd,0,sizeof(cmd));
	snprintf(cmd,sizeof(cmd),"led_send_message \"mesh;found\"");
	GPIO_FILE("cmd : %s\n", cmd);
	system(cmd);

}

char one_cc_rg_ssid_key(unsigned char *driv_ssid,unsigned char *driv_key){

	const char *json_str =NULL;
	char *output=NULL;

	unify_frame_invoke_dev_sta(&output,"get","DefaultConfig",NULL);
	GPIO_DEBUG("one_cc_rg_ssid_key output=%s\n",output);

	json_object *DefaultConfig = json_tokener_parse(output);
	json_object *isDefaultConfig=NULL;
	json_object_object_get_ex(DefaultConfig, "isDefaultConfig", &isDefaultConfig);
	GPIO_DEBUG("json_object_get_boolean(enable_obj)=%d\n",json_object_get_boolean(isDefaultConfig));

	if(json_object_get_boolean(isDefaultConfig)!=TRUE){/* 非默认的配置 */
		GPIO_DEBUG("It is not the default \n");
		json_object_put(DefaultConfig);
		free(output);
		return -1;
	}
	json_object_put(DefaultConfig);
	free(output);

	rg_wds_ssid_and_key(driv_ssid, driv_key);

	GPIO_DEBUG("%s :: driv_ssid=%s driv_ssid=%s\n", __func__, driv_ssid, driv_key);
	return 0;
}

void rg_wds_sync_countrycode(char* driver_countrycode) {
    char* json_str=NULL;
	char *config_output=NULL;
    unify_frame_invoke_dev_config(&json_str, "get", "country_code", NULL);
    GPIO_DEBUG("json_str=%s\n", json_str);
    /* {"radioList":[{"type":"5G","country":"CN"}],"version":"1.0.0","configId":"0","configTime":"0","currentTime":"0"} */
    json_object* parse_country_root = json_tokener_parse(json_str);
    json_object* radioList = json_object_object_get(parse_country_root, "radioList");
    json_object* radio = json_object_array_get_idx(radioList, 0);
    json_object* country_obj = json_object_object_get(radio, "country");
    const char* country_code = json_object_get_string(country_obj);
    json_object* type_obj = json_object_object_get(radio, "type");
    const char* type = json_object_get_string(type_obj);
    GPIO_FILE("country_code=%s\n", country_code);
    GPIO_FILE("type=%s\n", type);
    if (strncmp(driver_countrycode, country_code, 2) != 0) {
        /* 创建JSON根对象	  {"delay":"5","sn":[],"radioList":[{"type":"5G","country":"US"}]}*/
        json_object* country_root = json_object_new_object();

        /* 设置delay字段 */
        json_object_object_add(country_root, "delay", json_object_new_string("5"));

        /* 创建空数组sn */
        json_object_object_add(country_root, "sn", json_object_new_array());

        /* 创建radioList数组 */
        json_object* radioList = json_object_new_array();

        /*	创建radioList数组的元素对象 */
        json_object* radio = json_object_new_object();
        json_object_object_add(radio, "type", json_object_new_string(type));
        json_object_object_add(radio, "country", json_object_new_string(driver_countrycode));

        /* 将radio对象加入radioList数组 */
        json_object_array_add(radioList, radio);

        /* 将radioList数组加入根对象 */
        json_object_object_add(country_root, "radioList", radioList);

        /* 打印构造的JSON */
        GPIO_FILE("%s\n", json_object_to_json_string(country_root));
        unify_frame_invoke_dev_config(&config_output, "set", "country_code", json_object_to_json_string(country_root));
		GPIO_FILE("config_output=%s\n", json_object_to_json_string(country_root));
        json_object_put(country_root);
		free(config_output);
    }
    json_object_put(parse_country_root);
	free(json_str);
	sleep(8);
}


void est_fast_wds_set(fast_wds_info_t* fast_wds_info) {
	static char channel = 0;
	char cmd[128] = { 0 };
	char ret = 0;
	switch (fast_wds_info->func_mode) {
	case SCAN_PAIR: rg_wds_ssid_and_key(fast_wds_info->app_ssid, fast_wds_info->app_key);break;
	case ONE_CC:
		if (one_cc_rg_ssid_key(fast_wds_info->app_ssid, fast_wds_info->app_key) != 0) {
			return;
		}
		break;
	default:		break;
	}
	rg_wds_sync_countrycode(fast_wds_info->countrycode);
	if (fast_wds_info->channel != 0) {/* 当前信道和对端信道不一致 */
		snprintf(cmd, sizeof(cmd), "iwpriv %s set Channel=%d", rg_dev_capacity_table.wds_ifname, fast_wds_info->channel);
		GPIO_FILE("%s::%s\n", __func__, cmd);
		system(cmd);
		sleep(8);
	}
	pthread_mutex_lock(&wds_fast_pair_mtx);
	fast_wds_flag = 1;/* 桥接前只允许配对一次 */
	pthread_mutex_unlock(&wds_fast_pair_mtx);
	return;
}



void wifi_downup_file_exist_block(void) {

	if (access(WIFI_DWONUP_FILE, F_OK) != FAIL){
	GPIO_FILE("%s exists, blocking...\n", WIFI_DWONUP_FILE);/* 文件存在,准备进入轮询 */
		while (1){/* 不断检查文件是否存在 */
			if (access(WIFI_DWONUP_FILE, F_OK) == FAIL) {
				GPIO_FILE("%s File has been deleted, continuing...\n", WIFI_DWONUP_FILE);/* 文件被删除了	*/
				break;
			}
			sleep(1);
		}
	} else {
		GPIO_FILE("%s does not exist, continuing...\n", WIFI_DWONUP_FILE);/* 文件不存在 wifi初始化完成*/
	}
}

int rg_wds_beacon_pthread(void) {
    char ntv_sn[14];
	char send_sn_cmd[128];
	struct wds_beacon_info_s *wds_beacon_info;
    struct redis_rssi_info *redis_rssi;
	int len = 0;
	int pwstat_error_count = 0;
	int member_index = 0;
	wds_pw_info_t *wds_pw_info_tmp;

	wds_pw_arr_init();

	memset(ntv_sn, 0, sizeof(ntv_sn));
	wds_get_dev_sn(ntv_sn,sizeof(ntv_sn) - 1);
	GPIO_DEBUG("ntv_sn:%s", ntv_sn);
	wifi_downup_file_exist_block();
begin:
	while (1) {
	    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	    if (nl_fd < 0) {
	        perror("socket()");
			sleep(5);
	        continue;
	    }

	    memset(&nl_address, 0, sizeof(nl_address));
	    nl_address.nl_family = AF_NETLINK;
	    nl_address.nl_groups = 0;

	    if (bind(nl_fd, (struct sockaddr *) &nl_address, sizeof(nl_address)) < 0) {
	        perror("bind()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    nl_request_msg.n.nlmsg_type = GENL_ID_CTRL;//这是内核中genl_ctl的id
	    nl_request_msg.n.nlmsg_flags = NLM_F_REQUEST;
	    nl_request_msg.n.nlmsg_seq = 0;
	    nl_request_msg.n.nlmsg_pid = getpid();
	    nl_request_msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	    //Populate the payload's "family header" : which in our case is genlmsghdr
	    nl_request_msg.g.cmd = CTRL_CMD_GETFAMILY;
	    nl_request_msg.g.version = 0x1;
	    //Populate the payload's "netlink attributes"
	    nl_na = (struct nlattr *) GENLMSG_DATA(&nl_request_msg);//其实就相当于在nl_request_msg 的buf域中构造一个nla

	    nl_na->nla_type = CTRL_ATTR_FAMILY_NAME;
	    nl_na->nla_len = strlen("CONTROL_EXMPL") + 1 + NLA_HDRLEN;
	    strcpy(NLA_DATA(nl_na), "CONTROL_EXMPL"); //Family name length can be upto 16 chars including \0

	    nl_request_msg.n.nlmsg_len += NLMSG_ALIGN(nl_na->nla_len);

	    memset(&nl_address, 0, sizeof(nl_address));
	    nl_address.nl_family = AF_NETLINK;

	    len= sendto(nl_fd, (char *) &nl_request_msg, nl_request_msg.n.nlmsg_len,
	               0, (struct sockaddr *) &nl_address, sizeof(nl_address));
	    if (len != nl_request_msg.n.nlmsg_len) {
	        perror("sendto()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    len= recv(nl_fd, &nl_response_msg, sizeof(nl_response_msg), 0);
	    if (len < 0) {
	        perror("recv()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    if (!NLMSG_OK((&nl_response_msg.n), len)) {
	        fprintf(stderr, "family ID request : invalid message\n");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    if (nl_response_msg.n.nlmsg_type == NLMSG_ERROR) { //error
	        fprintf(stderr, "family ID request : receive error\n");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }

	    //解析出attribute中的family id
	    nl_na = (struct nlattr *) GENLMSG_DATA(&nl_response_msg);
	    nl_na = (struct nlattr *) ((char *) nl_na + NLA_ALIGN(nl_na->nla_len));
	    if (nl_na->nla_type == CTRL_ATTR_FAMILY_ID) {
	        nl_family_id = *(__u16 *) NLA_DATA(nl_na);//第一次通信就是为了得到需要的family ID
	    }

	    memset(&nl_request_msg, 0, sizeof(nl_request_msg));
	    memset(&nl_response_msg, 0, sizeof(nl_response_msg));

	    nl_request_msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	    nl_request_msg.n.nlmsg_type = nl_family_id;
	    nl_request_msg.n.nlmsg_flags = NLM_F_REQUEST;
	    nl_request_msg.n.nlmsg_seq = 60;
	    nl_request_msg.n.nlmsg_pid = getpid();
	    nl_request_msg.g.cmd = 1; //corresponds to DOC_EXMPL_C_ECHO;

	    nl_na = (struct nlattr *) GENLMSG_DATA(&nl_request_msg);
	    nl_na->nla_type = 1; // corresponds to DOC_EXMPL_A_MSG

	    nl_na->nla_len = sizeof(ntv_sn)+NLA_HDRLEN; //Message length
	    memcpy(NLA_DATA(nl_na), ntv_sn, sizeof(ntv_sn));

	    nl_request_msg.n.nlmsg_len += NLMSG_ALIGN(nl_na->nla_len);

	    memset(&nl_address, 0, sizeof(nl_address));
	    nl_address.nl_family = AF_NETLINK;
		GPIO_FILE("ntv_sn=%s %02X:%02X:%02X:%02X:%02X:%02X %s",ntv_sn, PRINT_MAC(rg_dev_info_t.sys_mac), rg_dev_info_t.dev_type);

		sprintf(send_sn_cmd, "iwpriv %s set bcn_est_ie=%s%%%02X:%02X:%02X:%02X:%02X:%02X%%%s", rg_dev_capacity_table.wds_ifname, ntv_sn, PRINT_MAC(rg_dev_info_t.sys_mac), rg_dev_info_t.dev_type);
		GPIO_DEBUG("send_sn_cmd=%s",send_sn_cmd);
		system(send_sn_cmd);
		//iwpriv rax set bcn_est_expend_info=ath_mac%dev_name%dev_nm_stat%prj_name%prj_nm_stat%pw_stat
		update_beacon_info();
		GPIO_DEBUG("send to");
	    len = sendto(nl_fd, (char *) &nl_request_msg, nl_request_msg.n.nlmsg_len,
	            0, (struct sockaddr *) &nl_address, sizeof(nl_address));
	    if (len != nl_request_msg.n.nlmsg_len) {
	        perror("sendto()");
	        close(nl_fd);
			sleep(5);
	        continue;
	    }
	    GPIO_FILE("Sent to kernel: %s\n",MESSAGE_TO_KERNEL);
		break;
	}

    while (1) {
       memset(&nl_response_msg, 0, sizeof(nl_response_msg));
	   len = recv(nl_fd, &nl_response_msg, sizeof(nl_response_msg), 0);
	   if (len < 0) {
	       perror("recv()");
           close(nl_fd);
           sleep(3);
           goto begin;
	   }

	    //异常处理
	   if (nl_response_msg.n.nlmsg_type == NLMSG_ERROR) { //Error
	   printf("Error while receiving reply from kernel: NACK Received\n");
	       close(nl_fd);
           sleep(3);
           goto begin;
	   }
	   if (len < 0) {
	       printf("Error while receiving reply from kernel\n");
	       close(nl_fd);
           sleep(3);
           goto begin;
	   }
	   if (!NLMSG_OK((&nl_response_msg.n), len)) {
	       printf("Error while receiving reply from kernel: Invalid Message\n");
	       close(nl_fd);
           sleep(3);
           goto begin;
	   }
		//GPIO_DEBUG("============NETLINK recv======");
	   //判断是密码状态还是beacon信息
	   //GPIO_DEBUG("nl_response_msg.g.cmd:%d",nl_response_msg.g.cmd);
	   if (nl_response_msg.g.cmd == DOC_KEYERROR) {
	   		GPIO_DEBUG("==========recv PW STATE from kernel=======");
			//解析收到的来自内核的密码状态信息
	   		len = GENLMSG_PAYLOAD(&nl_response_msg.n);
	  		nl_na = (struct nlattr *) GENLMSG_DATA(&nl_response_msg);

	   		wds_pw_info_tmp = (wds_pw_info_t *)NLA_DATA(nl_na);
	   		if (wds_pw_info_tmp !=NULL){
		   		GPIO_DEBUG("===========wds_pw_info.wds_pwstat=%d,wds_pw_info.keyerr_type:%d, dev_mac:%s, sn:%s, ath_mac:%02x:%02x:%02x:%02x:%02x:%02x", wds_pw_info_tmp->keyerr_type, wds_pw_info_tmp->wds_pwstat, wds_pw_info_tmp->dev_mac, wds_pw_info_tmp->sn, PRINT_MAC(wds_pw_info_tmp->ath_mac));
				member_index = wds_pw_arr_find_node(wds_pw_info_tmp->dev_mac);
				if (member_index != -1) {
					wds_pw_arr_update(wds_pw_info_tmp, member_index);
				}else {
					wds_pw_arr_add(wds_pw_info_tmp);
				}
	   		}
	   }else if(nl_response_msg.g.cmd == DOC_SSID_KEY){
			len = GENLMSG_PAYLOAD(&nl_response_msg.n);
			nl_na = (struct nlattr *) GENLMSG_DATA(&nl_response_msg);
			fast_wds_info_t *fast_wds_info = (fast_wds_info_t *)NLA_DATA(nl_na);
			est_fast_wds_set(fast_wds_info);
	   }else if(nl_response_msg.g.cmd == DOC_CALIBRATE_RSSI){
			len = GENLMSG_PAYLOAD(&nl_response_msg.n);
			nl_na = (struct nlattr *) GENLMSG_DATA(&nl_response_msg);
			redis_rssi = (struct redis_rssi_info *)NLA_DATA(nl_na);
                //GPIO_DEBUG("rssi mac:%02x:%02x:%02x:%02x:%02x:%02x",PRINT_MAC(redis_rssi->mac));
				//GPIO_DEBUG("uplink_rssi_h=%d ",redis_rssi->uplink_rssi_h);
				//GPIO_DEBUG("uplink_rssi_v=%d ",redis_rssi->uplink_rssi_v);
       			//GPIO_DEBUG("downlink_rssi_h=%d ",redis_rssi->downlink_rssi_h);
				//GPIO_DEBUG("downlink_rssi_v=%d ",redis_rssi->downlink_rssi_v);
#ifdef EST_SUPPORT_REDIS
            redbs_wds_rssi_set_pub(redis_rssi);
#endif
	   }else{
			//解析收到的来自内核的reply
		   len = GENLMSG_PAYLOAD(&nl_response_msg.n);
		   nl_na = (struct nlattr *) GENLMSG_DATA(&nl_response_msg);
		   wds_beacon_info = (struct wds_beacon_info_s *)NLA_DATA(nl_na);
		   //GPIO_DEBUG("*************************beacon***************************");
		   //GPIO_DEBUG("beacon mac:%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC(wds_beacon_info->mac));
		   //GPIO_DEBUG("beacon sn:%s", wds_beacon_info->sn);
		   pthread_mutex_lock(&mtx_wds_beacon_list);
		   rg_wds_beacon_process(wds_beacon_info);
		   pthread_mutex_unlock(&mtx_wds_beacon_list);
		   if(1 == wds_beacon_info->is_exist_expend){
				pthread_mutex_lock(&mtx_scan_dev_list);
		   		rg_wds_beacon_expand_process(wds_beacon_info);
		   		pthread_mutex_unlock(&mtx_scan_dev_list);
		   }

	   }

    }

    close(nl_fd);
    return 0;
}

//CPE此处为加入一个网络
void rg_wds_beacon_join_net_cpe() {
	static unsigned long time_off;
	struct sysinfo info;

	sysinfo(&info);

	if (rg_gpio_info_t.gpio_lock_value == LOCK) {
		time_off = info.uptime;
		return;
	}

	if (rg_ath_info_t.role == MODE_AP) {
		time_off = info.uptime;
		return;
	}

	if (time_off == 0) {
		time_off = info.uptime;
	}

	if (info.uptime - time_off > BEACON_CHECK_TMIE) {
		time_off = info.uptime;
	} else {
		return;
	}

	struct wds_ssid_netid_t *p;
	p = wds_list_find_max_rssi(rg_ath_info_t.role);
	if (p == NULL) {
		GPIO_DEBUG("can not find other ssid,sorry!");
		return;
	}
	GPIO_DEBUG("now best ssid is %s ,ap rssi is %d,cpe rssi is %d",p->wds_ssid,p->rssi_ap,p->rssi_cpe);
	if (memcmp(p->wds_ssid,rg_ath_info_t.ssid,33) != 0) {
		if (rg_pair_info_heap_t == NULL) {
			rg_wds_ath_set_ssid(p->wds_ssid);
			rg_wds_ath_reload_wifi();
			rg_wds_ath_update(&rg_ath_info_t);
		} else {
			if (wds_list_rssi_compare(p,rg_pair_info_heap_t->pair_assioc_info_t.rssi)) {
				rg_wds_ath_set_ssid(p->wds_ssid);
				rg_wds_ath_reload_wifi();
				rg_wds_ath_update(&rg_ath_info_t);
			}
		}
	}
}

//ap此处为加入一个网络
void rg_wds_beacon_join_net_ap() {
	static unsigned long time_off;
	struct sysinfo info;

	sysinfo(&info);

	if (rg_gpio_info_t.gpio_lock_value == LOCK) {
		time_off = info.uptime;
		return;
	}

	if (rg_ath_info_t.role == MODE_CPE) {
		time_off = info.uptime;
		return;
	}

	if (time_off == 0) {
		time_off = info.uptime;
	}

	if (info.uptime - time_off > BEACON_CHECK_TMIE) {
		time_off = info.uptime;
	} else {
		return;
	}

	struct wds_ssid_netid_t *p;
	p = wds_list_find_max_rssi(rg_ath_info_t.role);
	if (p == NULL) {
		return;
	}
	GPIO_DEBUG("now best ssid is %s ,ap rssi is %d,cpe rssi is %d",p->wds_ssid,p->rssi_ap,p->rssi_cpe);
	if (memcmp(p->wds_ssid,rg_ath_info_t.ssid,33) != 0) {
		if (rg_pair_info_heap_t == NULL) {
			rg_wds_ath_set_ssid(p->wds_ssid);
			rg_wds_ath_reload_wifi();
			rg_wds_ath_update(&rg_ath_info_t);
		} else {
			if (wds_list_rssi_compare(p,rg_pair_info_heap_t->pair_assioc_info_t.rssi)) {
				rg_wds_ath_set_ssid(p->wds_ssid);
				rg_wds_ath_reload_wifi();
				rg_wds_ath_update(&rg_ath_info_t);
			}
		}
	}
}
