#include "rg_wds.h"
#include <openssl/md5.h>
#include "was_sdk.h"

/*
type:set/get/info  0/1/2/
    set:设置即可
    get:获取信息，通过shell执行
    info:发送一般信息
dest:sn
    目标设备
dest:sn#type:set#cmd:具体指令
dest:sn#type:info#role:cpe/ap#lock::on/off#
*/

#define LIST_ALL_PAGE_SIZE  4
#define DEV_MULTI_MAXCNT    200

int g_dev_multi_info_cnt = 0;
int g_count_down = 0;
struct dev_multi_info *rg_wds_all_info = NULL;
pthread_mutex_t mtx_rg_wds_all_info;
pthread_cond_t cond_rg_wds_all_info;
pthread_mutex_t rg_wds_crypt_mtx;

char *rg_wds_to_set_middle(char *buf) {
    memcpy(buf,":",1);
    return buf + 1;
}

char *rg_wds_to_set_end(char *buf) {
    memcpy(buf,"#",1);
    return buf + 1;
}

char *rg_wds_to_set_begin(char *buf) {
    memcpy(buf,"#",1);
    return buf + 1;
}

char * rg_wds_to_dev_head(char mem_type,char *sn,char *buf) {
    char *p = buf;
    memcpy(p,"dest",strlen("dest"));
    p += strlen("dest");
    p = rg_wds_to_set_middle(p);

    memcpy(p,sn,strlen(sn));
    p += strlen(sn);
    p = rg_wds_to_set_end(p);

    memcpy(p,"type",strlen("type"));
    p += strlen("type");
    p = rg_wds_to_set_middle(p);

    switch (mem_type) {
        case TYPE_SET:
            memcpy(p,"set",strlen("set"));
            p += strlen("set");
            break;
        case TYPE_GET:
            memcpy(p,"get",strlen("get"));
            p += strlen("get");
            break;
        case TYPE_INFO:
            memcpy(p,"info",strlen("info"));
            p += strlen("info");
            break;
        case TYPE_CRYPTO:
            memcpy(p,"crypto",strlen("crypto"));
            p += strlen("crypto");
            break;
        default:
            memcpy(p,"info",strlen("info"));
            p += strlen("info");
    }
    p = rg_wds_to_set_end(p);
    return p;
}

char * rg_wds_to_dev_body(char *buf,char *str) {
    char *p = buf;

    memcpy(p,str,strlen(str));
    p += strlen(str);
}

void rg_wds_to_dev_message(char type,char *sn,char *buf,char *str) {
    char *p = buf;

    p = rg_wds_to_set_begin(p);
    p = rg_wds_to_dev_head(type,sn,p);
    p = rg_wds_to_dev_body(p,str);
    p = rg_wds_to_set_end(p);
}

//根据SN判断是否是发送给自己的
char rg_wds_check_1(char *str) {
    int i = 0;
    char *p;

    while(str[i] != ':' && str[i] != 0) {
        i++;
    }

    if (str[i] == ':') {
        p = str + i + 1;
        if (memcmp(p,rg_dev_info_t.sn,strlen(rg_dev_info_t.sn)) == 0 || memcmp(p,"all",strlen("all")) == 0) {
            return 1;
        }
    }
    return 0;
}

//消息类型
char rg_wds_type_process(char *str) {
    int i = 0;
    char *p;

    while(str[i] != ':' && str[i] != 0) {
        i++;
    }

    if (str[i] == ':') {
        p = str + i + 1;
        if (memcmp(p,"set",strlen("set")) == 0) {
            return TYPE_SET;
        } else if (memcmp(p,"get",strlen("get")) == 0) {
            return TYPE_GET;
        } else if (memcmp(p,"info",strlen("info")) == 0) {
            return TYPE_INFO;
        } else if (memcmp(p,"crypto",strlen("crypto")) == 0) {
            return TYPE_CRYPTO;
        }
    }
    return 0;
}

char *rg_wds_info_item_filter(char *buf) {
    if ((buf - 1) != NULL && *(buf - 1) == ';') {
        return buf;
    }
    memcpy(buf,";",1);
    return buf + 1;
}

char *rg_wds_info_item_str(char *option,char *value,char *buf) {
    char *p = buf;
    if (strlen(value) == 0) {
        return p;
    }
    memcpy(p,option,strlen(option));
    p = p + strlen(option);
    memcpy(p,":",strlen(":"));
    p = p + strlen(":");
    memcpy(p,value,strlen(value));
    p = p + strlen(value);
    return p;
}

char *rg_wds_info_item_clean_value_str(char *option,char *buf) {
    char *p = buf;
    if(!option || !buf){
		GPIO_ERROR("option==null or buf==null !!!");
		return NULL;
	}
    memcpy(p,option,strlen(option));
    p = p + strlen(option);
    memcpy(p,":",strlen(":"));
    p = p + strlen(":");
    return p;
}

char *rg_wds_info_item_str_len(char *option,char *value,int len,char buf) {
    char *p = buf;

    memcpy(p,option,strlen(option));
    p = p + strlen(option);
    memcpy(p,":",strlen(":"));
    p = p + strlen(":");
    memcpy(p,value,len);
    p = p + len;
}

/*
char *rg_wds_info_item_num(char *option,unsigned int value,char buf) {
    char *p = buf;

    memcpy(p,option,strlen(option));
    p = p + strlen(option);
    memcpy(p,":",strlen(":"));
    p = p + strlen(":");

    (unsigned int) (char *) p = (unsigned int)value;
    p = p + sizeof(value);
}
*/

void rg_wds_set_array_value(int value,int array[],int len) {
    array[array[len - 1]] = value;
    array[len - 1] = array[len - 1] + 1;
    if (array[len - 1] == len - 1 - 1) {
        array[len - 1] = 0;
    }
    //DEBUG("value %d array[len - 1] %d len %d",value,array[len - 1],len);
}

unsigned int rg_wds_get_array_average(int array[],int len) {
    int i = 0;
    int count = 0;
    long sum = 0;
    //DEBUG("");
    for (i = 0;i < (len - 1);i++) {
        if (array[i] != 0) {
            //DEBUG("array[%d] = %d,count %d",i,array[i],count + 1);
            sum += array[i];
            count++;
        }
    }
    if (count == 0) {
        return 0;
    }
    //DEBUG("average %d",sum/count);
    return sum/count;
}

int get_peer_info(char * buf, char * name, int buf_len){
	struct json_object *wds_info_obj, *obj, *arr;
	int length;
	int str_len;
	int resoult = FAIL;
	int dev_num;
	char* wds_info, *re_str, dev_num_s[5];
	wds_info = ReadFile(PEER_WDS_INFO, &length);
    if(NULL == wds_info){
        GPIO_ERROR("(err)Open file[%s] fail!", PEER_WDS_INFO);
        goto end;
    }
    wds_info_obj = json_tokener_parse((const char *)wds_info);
    if (is_error(wds_info_obj)) {
        GPIO_ERROR("(err)Fail to get wds_info json string!");
        goto end;
    }
	obj = json_object_object_get(wds_info_obj, "LIST_NUM");
	if (!obj) {
        GPIO_ERROR("LIST_NUM is NULL!");
        goto end;
    }
	re_str = json_object_to_json_string(obj);
	if (!re_str) {
        GPIO_ERROR("(list_num)re_str is NULL!");
        goto end;
    }
	memset(dev_num_s, 0, sizeof(dev_num_s));
	str_len = strlen(re_str) - 2;
	strncpy(dev_num_s, (unsigned char *)(re_str + 1), str_len);
	dev_num = atoi(dev_num_s);
	if(dev_num<=0){
		GPIO_WARNING("(warning)list_num = %d go to end", dev_num);
		goto end;
	}
	arr = json_object_object_get(wds_info_obj, "LIST");
    if (!arr) {
        GPIO_ERROR("LIST is NULL!");
        goto end;
    }
	
	obj = json_object_array_get_idx(arr, dev_num-1);
	if (!obj) {
        GPIO_ERROR("LIST[0] is NULL!");
        goto end;
    }
	obj = json_object_object_get(obj, name);
	if (!obj) {
        GPIO_ERROR("%s is NULL!", name);
        goto end;
    }

	re_str = NULL;
	re_str = json_object_to_json_string(obj);
	if (!re_str) {
        GPIO_ERROR("(%s)re_str is NULL!", name);
        goto end;
    }
	
	str_len = 0;
	str_len = strlen(re_str) - 2;
	
	if(str_len > buf_len){
		GPIO_ERROR("Buf is too small!!!");
		goto end;
	}
	
    strncpy(buf, (unsigned char *)(re_str + 1), str_len);
	
	resoult = SUCESS;
	
end:
	if (wds_info_obj) {
		json_object_put(wds_info_obj);
		wds_info_obj = NULL;
	}
	
	if (wds_info) {
		free(wds_info);
		wds_info = NULL;
	}
	return resoult;
}




static int tx_speed_a[100];
static int rx_speed_a[100];
static int rssi_a[100];
static int chutil_a[100];
bool is_arry_all_zero(char* arry, int len){
	int i = 0;
	for (i=0; i<6;i++) {
		if (arry[i] !=0){
			return false;
		}
	}
	return true;
}  


int get_network_connect(char *buf, int buf_len) {
	int ret = FAIL;
	char* json_str = NULL;
	json_object* parse_network_root = NULL;
	json_object* connected_obj = NULL;
	const  char* connected = NULL;

    unify_frame_invoke_dev_sta(&json_str, "get", "networkConnect", NULL);
	if (json_str==NULL) {
		GPIO_DEBUG("json_str==NULL");
		goto nw_end;
	}
	GPIO_DEBUG("json_str=%s", json_str);
    /* {"rcode":"00000000","connnected":"true","message":""} */
	
    parse_network_root = json_tokener_parse(json_str);
	if (parse_network_root==NULL) {
		GPIO_DEBUG("parse_network_root==NULL");
		goto nw_end;
	}

	connected_obj = json_object_object_get(parse_network_root, "connnected");
	if (connected_obj==NULL) {
		GPIO_DEBUG("connected_obj==NULL");
		goto nw_end;
	}
	
    connected = json_object_get_string(connected_obj);
    if (connected==NULL) {
		GPIO_DEBUG("connected==NULL");
		goto nw_end;
	}
    GPIO_DEBUG("connected=%s", connected);
	
	if (buf_len>strlen(connected)) {
		strncpy(buf, connected, strlen(connected));
		ret = SUCESS;
	}
	
nw_end:
	if (parse_network_root!=NULL) {
		json_object_put(parse_network_root);
	}
	if (json_str!=NULL) {
		free(json_str);
	}

	return ret;
}

void *rg_wds_get_ioctl_msg(const char *ifname, char *wl_cmd)
{
	int ret = 0;
	rj_stainfo_t *asso_info = NULL;
    char msg[MAC_TAB_SIZE];
	int msg_type;

	if(strcmp(wl_cmd, "show_apcli_list") == 0) {
		msg_type = RJ_WAS_SHOW_APLCLI_INFO_EN;	
	}
	else if(strcmp(wl_cmd, "list radio") == 0){
		msg_type = RJ_WAS_GET_RADIOINFO_EN;
	}
	else{
		return NULL;
	}
	
	ret = was_ext_ioctl_msg(msg, sizeof(msg), ifname, msg_type, false);
    if (ret != WAS_E_NONE) {
        GPIO_DEBUG("wlanconfig result is failed");
       	return NULL;
    }

	return msg;	
}	

char *rg_wds_info_body(char *buf) {
    char *p = buf;
	struct sysinfo info;
	struct in_addr user_ip_in;
    static unsigned char flag = 0;
    static unsigned long time_now;
    unsigned char str[100], str_2[100], wl_cmd_suffix[20];
	GPIO_DEBUG("==========>>start get info body:");
	sysinfo(&info);        //获取当前时间
	
    p = rg_wds_info_item_str("sn",rg_dev_info_t.sn,p);
    p = rg_wds_info_item_filter(p);
    GPIO_DEBUG("sn:%s",rg_dev_info_t.sn);
    p = rg_wds_info_item_str("hostname",rg_dev_info_t.host_name,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("ssid",rg_ath_info_t.ssid,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
	//GPIO_DEBUG("=========%02x:%02x:%02x:%02x:%02x:%02x", rg_dev_info_t.sys_mac[0],rg_dev_info_t.sys_mac[1],rg_dev_info_t.sys_mac[2],rg_dev_info_t.sys_mac[3],rg_dev_info_t.sys_mac[4],rg_dev_info_t.sys_mac[5]);
    sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",PRINT_MAC(rg_dev_info_t.sys_mac));
    p = rg_wds_info_item_str("sysmac",str,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("model",rg_dev_info_t.dev_type,p);
    p = rg_wds_info_item_filter(p);

	p = rg_wds_info_item_str("lock",rg_gpio_info_t.gpio_lock_value==LOCK ? "true":"false",p);
    p = rg_wds_info_item_filter(p);
	
    memset(str,0,sizeof(str));
	sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",PRINT_MAC(rg_ath_info_t.root_mac_hex));
	GPIO_DEBUG("athmac:%s", str);
    p = rg_wds_info_item_str("athmac",str,p);
    p = rg_wds_info_item_filter(p);
	
	memset(wl_cmd_suffix, 0, sizeof(wl_cmd_suffix));
	GPIO_DEBUG("role:%d", rg_ath_info_t.role);
      
    if (rg_ath_info_t.role == MODE_CPE && rg_pair_info_heap_t != NULL) {
		
		//cpe收到对端的信息后直接保存到tmp文件里了，ap保存到了链表里
		//so get peer from 
		memset(str, 0, sizeof(str));
		int length;
		char *ap_sn = ReadFile(AP_SN, &length);
		if (ap_sn){
			strncpy(str,ap_sn,length);
			free(ap_sn);
			ap_sn = NULL;
	        p = rg_wds_info_item_str("peersn", str, p);
			GPIO_DEBUG("peersn:%s", str);
	        p = rg_wds_info_item_filter(p);
		}else{
			GPIO_ERROR("get ap_sn[ %s ]fail", AP_SN);
		}
		memset(str,0,sizeof(str));
        sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",PRINT_MAC(rg_pair_info_heap_t->mac));
        p = rg_wds_info_item_str("peermac",str,p);
        p = rg_wds_info_item_filter(p);

		int rssi;
        rssi = rg_pair_info_heap_t->pair_assioc_info_t.rssi;
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rssi);
        p = rg_wds_info_item_str("rssi",str,p);
        p = rg_wds_info_item_filter(p);
		GPIO_DEBUG("rssi:%s", str);
		
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.rxrate);
        p = rg_wds_info_item_str("rate",str,p);
        p = rg_wds_info_item_filter(p);

		memset(str, 0, sizeof(str));
		if(20 == rg_pair_info_heap_t->pair_assioc_info_t.BW){
			sprintf(str, "%s", "IEEE80211_MODE_11AC_VHT20");
		}else if (40 == rg_pair_info_heap_t->pair_assioc_info_t.BW){
			sprintf(str, "%s", "IEEE80211_MODE_11AC_VHT40");
		}else if(80 == rg_pair_info_heap_t->pair_assioc_info_t.BW){
			sprintf(str, "%s", "IEEE80211_MODE_11AC_VHT80");
		}
		
        p = rg_wds_info_item_str("phymode", str, p);
        p = rg_wds_info_item_filter(p);
		GPIO_DEBUG("phymode:%s", str);
		
        rg_wds_set_array_value(rssi,rssi_a,sizeof(rssi_a)/sizeof(int));
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_wds_get_array_average(rssi_a,sizeof(rssi_a)/sizeof(int)));
        p = rg_wds_info_item_str("rssi_a",str,p);
        p = rg_wds_info_item_filter(p);
		GPIO_DEBUG("rssi_a:%s", str);

		memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.rxrate);
        p = rg_wds_info_item_str("rx_speed",str,p);
        p = rg_wds_info_item_filter(p);

        rg_wds_set_array_value(rg_pair_info_heap_t->pair_assioc_info_t.rxrate,
			                                                rx_speed_a,
			                                sizeof(rx_speed_a)/sizeof(int));
        memset(str,0,sizeof(str));
		int rx_speed_i = rg_wds_get_array_average(           rx_speed_a, 
			                                  sizeof(rx_speed_a)/sizeof(int));
        sprintf(str, "%d", rx_speed_i);
        p = rg_wds_info_item_str("rx_speed_a",str,p);
        p = rg_wds_info_item_filter(p);

        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.txrate);
        p = rg_wds_info_item_str("tx_speed",str,p);
        p = rg_wds_info_item_filter(p);

        rg_wds_set_array_value(rg_pair_info_heap_t->pair_assioc_info_t.txrate,
			                                                tx_speed_a,
			                                sizeof(tx_speed_a)/sizeof(int));
        memset(str, 0, sizeof(str));
		int tx_speed_i = rg_wds_get_array_average( 		    tx_speed_a, 
											  sizeof(tx_speed_a)/sizeof(int));
        sprintf(str, "%d", tx_speed_i);
        p = rg_wds_info_item_str("tx_speed_a", str, p);
        p = rg_wds_info_item_filter(p);

        memset(str, 0, sizeof(str));
        rg_wds_misc_read_file("/tmp/.tipc_ping_time",str,sizeof(str));
        p = rg_wds_info_item_str("pingTime",str,p);
        p = rg_wds_info_item_filter(p);

        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.assioc_time);
        p = rg_wds_info_item_str("connectTime",str,p);
        p = rg_wds_info_item_filter(p);

		sprintf(wl_cmd_suffix, "%s", "show_apcli_list");
		
    }else {

		sprintf(wl_cmd_suffix, "%s", "list radio");
		
	}
	char get_uci_wds_pw_cmd[50];
	memset(get_uci_wds_pw_cmd, 0, sizeof(get_uci_wds_pw_cmd));
	if (rg_ath_info_t.role == MODE_CPE){
		p = rg_wds_info_item_str("role","cpe",p);
        p = rg_wds_info_item_filter(p);
        sprintf(get_uci_wds_pw_cmd, CMD_GET_WDS_DF_PW, rg_dev_capacity_table.wifi_name, "ApCliWPAPSK");

        void *sta_data = NULL;
        rj_stainfo_t *sta_info =NULL;
        sta_data = rg_wds_get_ioctl_msg(rg_ath_info_t.ath_wds_name, wl_cmd_suffix);
        sta_info = (rj_stainfo_t *)sta_data;

        memset(str,0,sizeof(str));
        sprintf(str, "%llu", sta_info->sta_rxbyte);
        GPIO_DEBUG("CPE:rxflow:%s", str);
		
        //p = rg_wds_info_item_str("rxflow",str,p);
		p = rg_wds_info_item_str("rx_rate",str,p);
        p = rg_wds_info_item_filter(p);


        memset(str,0,sizeof(str));
        sprintf(str, "%llu", sta_info->sta_txbyte);
        GPIO_DEBUG("CPE:txflow:%s", str);

        //p = rg_wds_info_item_str("txflow",str,p);
		p = rg_wds_info_item_str("tx_rate",str,p);
        p = rg_wds_info_item_filter(p);
		
	}else {
		p = rg_wds_info_item_str("role","ap",p);
        p = rg_wds_info_item_filter(p);
		sprintf(get_uci_wds_pw_cmd, CMD_GET_WDS_DF_PW, rg_ath_info_t.ath_wds_name, "key");

	    unsigned long rx_rate = 0;
    	unsigned long tx_rate = 0;
    	rg_wds_get_dev_flow(&rx_rate,&tx_rate);
    	GPIO_DEBUG("AP:rx_rate %d tx_rate %d",rx_rate,tx_rate);
    	memset(str,0,sizeof(str));
    	sprintf(str,"%d",rx_rate);
    	p = rg_wds_info_item_str("rx_rate",str,p);
    	p = rg_wds_info_item_filter(p);
    
    	memset(str,0,sizeof(str));
    	sprintf(str,"%d",tx_rate);
    	p = rg_wds_info_item_str("tx_rate",str,p);
    	p = rg_wds_info_item_filter(p);

		memset(str, 0, sizeof(str));
	}
	
	//Use to determine if it is the default password
	memset(str, 0, sizeof(str));
	GPIO_DEBUG("get_uci_wds_pw_cmd:", get_uci_wds_pw_cmd);
	rg_wds_uci_get_param(get_uci_wds_pw_cmd, str, sizeof(str));
	
	char df_pw[10];
	memset(df_pw, 0, sizeof(df_pw));
	//GPIO_DEBUG("======uci_pw:%s ; %s:%s", str, WDS_DF_PW_FILE, str_2);
	if(strcmp(str, WDS_DF_PW) == 0){
		sprintf(df_pw, "%s", "1");
	}else {
		sprintf(df_pw, "%s", "0");
	}
	//GPIO_DEBUG("def_pw:%s", df_pw);
	//Default password or not
	p = rg_wds_info_item_str("def_pw", df_pw, p);
	p = rg_wds_info_item_filter(p);

	//Whether password Settings are supported
	memset(str, 0, sizeof(str));
	p = rg_wds_info_item_str("wds_pw", rg_dev_capacity_table.wds_pw, p);
	p = rg_wds_info_item_filter(p);
	
	void *ioctl_data = NULL;
	rj_stainfo_t  *stainfo = NULL;
	rj_radioinfo_t *radio_info = NULL;
	ioctl_data = rg_wds_get_ioctl_msg(rg_ath_info_t.ath_wds_name, wl_cmd_suffix);
	if(strcmp(wl_cmd_suffix, "show_apcli_list") == 0) {
		stainfo = (rj_stainfo_t *)ioctl_data;
		memset(str, 0, sizeof(str));
		memset(str_2, 0, sizeof(str_2));
		sprintf(str, "%d", stainfo->floornoise);
		GPIO_DEBUG("floornoise:%s", str);
		sprintf(str_2, "%d", stainfo->utilization);
		GPIO_DEBUG("chutil:%s", str_2);
	}
	else {
		radio_info = (rj_radioinfo_t *)ioctl_data;
		memset(str, 0, sizeof(str));
		memset(str_2, 0, sizeof(str_2));
		sprintf(str, "%d", radio_info->floornoise);
		GPIO_DEBUG("floornoise:%s", str);
		sprintf(str_2, "%d", radio_info->utilization);
		GPIO_DEBUG("chutil:%s", str_2);
	}

    p = rg_wds_info_item_str("channf",str,p);
    p = rg_wds_info_item_filter(p);

	int int_chutil= atoi(str_2)/100.0 * 255;//驱动以及换算出来了百分比，web要做乘以255操作
	GPIO_DEBUG("baifenbi:%f, chutil:%d", atoi(str_2)/100.0, int_chutil);
	memset(str, 0, sizeof(str));
	sprintf(str, "%d", int_chutil);
    p = rg_wds_info_item_str("chutil", str, p);
    p = rg_wds_info_item_filter(p);
    //平均空口利用率
    rg_wds_set_array_value(atoi(str),chutil_a,sizeof(chutil_a)/sizeof(int));
    memset(str,0,sizeof(str));
    sprintf(str,"%d",rg_wds_get_array_average(chutil_a,sizeof(chutil_a)/sizeof(int)));
    p = rg_wds_info_item_str("chutil_a",str,p);
    p = rg_wds_info_item_filter(p);
	
	memset(str,0,sizeof(str));
	GPIO_DEBUG("rg_dev_info_t.software_version:%s", rg_dev_info_t.software_version);
	char * delimiter = strchr(&rg_dev_info_t.software_version, ';');
	if(delimiter){
		GPIO_DEBUG("Use the new version number.[ %s ]", rg_dev_info_t.software_version);
		int ver_len = strlen(delimiter);
		strncpy(str, delimiter+1, ver_len-1);

		memset(str_2, 0, sizeof(str_2));
		ver_len = strlen(rg_dev_info_t.software_version) -ver_len;
		strncpy(str_2, rg_dev_info_t.software_version, ver_len);
		GPIO_DEBUG("body softver_new:%s", str_2);
		p = rg_wds_info_item_str("softver_new",str_2,p);
    	p = rg_wds_info_item_filter(p);
	}else{
		strncpy(str, rg_dev_info_t.software_version, strlen(rg_dev_info_t.software_version));
		GPIO_DEBUG("Use the old version number.[ %s ]", str);
		//p = rg_wds_info_item_clean_value_str("softver_new", p); //用于清空有ReyeeOS的残留
		GPIO_DEBUG("body clean_sftn:1");
		p = rg_wds_info_item_str("clean_sftn", "1", p);//Used to clear residual "ReyeeOS" in "softver_new" 
		p = rg_wds_info_item_filter(p);
	}
	GPIO_DEBUG("body softversion:%s", str);
	p = rg_wds_info_item_str("softversion",str,p);
    p = rg_wds_info_item_filter(p);
	

	
    user_ip_in.s_addr = rg_dev_info_t.ip;
    p = rg_wds_info_item_str("userIp", inet_ntoa(user_ip_in), p);
    p = rg_wds_info_item_filter(p);
	//GPIO_DEBUG("userIP:%s", inet_ntoa(user_ip_in));

    if (rg_dev_capacity_table.radio == MNG_2G_WDS_2G) {
        p = rg_wds_info_item_str("band","2.4G",p);
        p = rg_wds_info_item_filter(p);
    } else if (rg_dev_capacity_table.radio == MNG_5G_WDS_5G) {
        p = rg_wds_info_item_str("band","5.8G",p);
        p = rg_wds_info_item_filter(p);
    } else if (rg_dev_capacity_table.radio == MNG_2G_WDS_5G) {
        p = rg_wds_info_item_str("band","5.8G",p);
        p = rg_wds_info_item_filter(p);
    }

    memset(str,0,sizeof(str));
    sprintf(str,"%d",info.uptime);
    p = rg_wds_info_item_str("onlineTime",str,p);
    p = rg_wds_info_item_filter(p);
	
    if (rg_pair_info_heap_t != NULL) {
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.channel);
        p = rg_wds_info_item_str("channel",str,p);
        p = rg_wds_info_item_filter(p);
    } else {
        memset(str,0,sizeof(str));
        memset(str_2,0,sizeof(str_2));
        sprintf(str,CMD_GET_CHANNEL,rg_dev_capacity_table.wifi_name);
        rg_wds_uci_get_param(str,str_2,sizeof(str_2));
		GPIO_DEBUG("CMD_GET_CHANNEL %s:%s", str, str_2);
        p = rg_wds_info_item_str("channel",str_2,p);
        p = rg_wds_info_item_filter(p);
    }
	
    p = rg_wds_info_item_str("distance",rg_ath_info_t.wds_distance,p);
	GPIO_DEBUG("distance=%s",rg_ath_info_t.wds_distance);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("txpower",rg_ath_info_t.wds_txpower,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
    rg_wds_misc_get_iface_netmask("br-wan",str);
    p = rg_wds_info_item_str("netmask",str,p);
    p = rg_wds_info_item_filter(p);

    if (rg_pair_info_heap_t != NULL) {
        p = rg_wds_info_item_str("onlinestatus","online",p);
        p = rg_wds_info_item_filter(p);
    } else {
        p = rg_wds_info_item_str("onlinestatus","offline",p);
        p = rg_wds_info_item_filter(p);
    }

	memset(str_2, 0, sizeof(str_2));
	strcpy(str_2, "true");
	GPIO_DEBUG("networkConnect set fixed value:%s",str_2);

    if (strcmp(str_2,"true") == 0) {
        p = rg_wds_info_item_str("cwmp","on",p);
        p = rg_wds_info_item_filter(p);
        GPIO_DEBUG("networkConnect connect sucess!!!!!");
    } else if(strcmp(str_2,"false") == 0) {
        p = rg_wds_info_item_str("cwmp","off",p);
        p = rg_wds_info_item_filter(p);
        GPIO_DEBUG("networkConnect donnot connect sucess!!!!!");
    }
    //一分钟发送一次
    if (time_now == 0 || (info.uptime - time_now) > 5) {
        time_now = info.uptime;
        char speed[10];
        char link[10];
        char duplex[10];
        int i;
		int sw_flag;
        for (i = 0; i < rg_dev_capacity_table.switch_num; i++) {
            if (-1 == rg_dev_capacity_table.switch_port[i]) {
                continue;
            }
            memset(speed,0,sizeof(speed));
            memset(link,0,sizeof(link));
            memset(duplex,0,sizeof(duplex));
			GPIO_DEBUG("switch_name:%s, port:%d, i=%d", rg_dev_capacity_table.switch_name,
				rg_dev_capacity_table.switch_port[i],
				i);
            rg_wds_sw_status_status(rg_dev_capacity_table.switch_name,
				                   rg_dev_capacity_table.switch_port[i],
				                                   link,speed,duplex);
            
            memset(str,0,sizeof(str));
            sprintf(str,"lan%dspeed",i+1);
            p = rg_wds_info_item_str(str,speed,p);
            p = rg_wds_info_item_filter(p);
			GPIO_DEBUG("%s=%s", str, speed);

            memset(str,0,sizeof(str));
            sprintf(str,"lan%dlink",i+1);
            p = rg_wds_info_item_str(str,link,p);
            p = rg_wds_info_item_filter(p);
			GPIO_DEBUG("%s=%s", str, link);

            memset(str,0,sizeof(str));
            sprintf(str,"lan%dduplex",i+1);
            p = rg_wds_info_item_str(str,duplex,p);
            p = rg_wds_info_item_filter(p);
			GPIO_DEBUG("%s=%s", str, duplex);

			memset(str,0,sizeof(str));
            sprintf(str, "lan%dnosupport", i+1);
			p = rg_wds_info_item_str(str,"0",p);
            p = rg_wds_info_item_filter(p);
			GPIO_DEBUG("%s=%s", str, "0");
			
        }

		if (rg_dev_capacity_table.switch_num==1){
			memset(str,0,sizeof(str));
            sprintf(str, "lan%dnosupport", 2);
			p = rg_wds_info_item_str(str,"1",p);
            p = rg_wds_info_item_filter(p);
			GPIO_DEBUG("%s=%s", str, "1");
		}
    }

	/*
    unsigned long rx_rate = 0;
    unsigned long tx_rate = 0;
    rg_wds_get_dev_flow(&rx_rate,&tx_rate);
    GPIO_DEBUG("fuxf---------------------------rx_rate %d tx_rate %d",rx_rate,tx_rate);
    memset(str,0,sizeof(str));
    sprintf(str,"%d",rx_rate);
    p = rg_wds_info_item_str("rx_rate",str,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
    sprintf(str,"%d",tx_rate);
    p = rg_wds_info_item_str("tx_rate",str,p);
    p = rg_wds_info_item_filter(p);
	*/
    p = rg_wds_info_item_str("hardversion",rg_dev_info_t.hardware_version,p);
    p = rg_wds_info_item_filter(p);

#ifdef EST_SUPPORT_REDIS  
    struct dev_multi_info *redis_wds_info = NULL;
    char *dec_local,*dec_redis;
    char str_3[100],str_4[100],str_5[100],str_6[100];
    bool b_pw_flag = false;   
    memset(str_3, 0, sizeof(str_3));
    memset(str_4, 0, sizeof(str_4));
    memset(str_5, 0, sizeof(str_5));
    memset(str_6, 0, sizeof(str_6));
#endif
    memset(str,0,sizeof(str));
    rg_wds_misc_read_file(EWEB_PW_FILE, str, sizeof(str));
    if (strlen(str) == 0) {
        memcpy(str, EWEB_DEF_PW, strlen(EWEB_DEF_PW));
		GPIO_DEBUG("%s is null, set def password", EWEB_PW_FILE);
        rg_wds_misc_write_file(EWEB_PW_FILE,EWEB_DEF_PW,strlen(EWEB_DEF_PW));
	} 
#ifdef EST_SUPPORT_REDIS  
    else {
	pthread_mutex_lock(&rg_wds_crypt_mtx);
        dec_local = rg_crypto_buf_decrypt(str, strlen(str), 'c');
        //GPIO_DEBUG("pwd decrypto:%s",dec_local);
        if(dec_local == NULL){
            pthread_mutex_unlock(&rg_wds_crypt_mtx);
        } else {
            strcpy(str_5,dec_local);
            rg_crypto_buf_free(dec_local);
            pthread_mutex_unlock(&rg_wds_crypt_mtx);
            
            if(strcmp(str_5,EWEB_DEF_PW_DC) == 0 && (rg_ath_info_t.role == MODE_CPE)) {
                unsigned char peer_sn[30];
                b_pw_flag = true;
                redis_wds_info = malloc(sizeof(struct dev_multi_info));
                if(redis_wds_info != NULL) {
                    memset(redis_wds_info, 0, sizeof(struct dev_multi_info));
                    if(0 == redbs_wds_info_get_pub(rg_dev_info_t.sn,redis_wds_info)){
                        strcpy(peer_sn,redis_wds_info->peer_sn);
                        memset(redis_wds_info, 0, sizeof(struct dev_multi_info));
                        if(0 == redbs_wds_info_get_pub(peer_sn,redis_wds_info)){
                            memset(str_2, 0, sizeof(str_2));
                            strcpy(str_2,redis_wds_info->passwd);
                            dec_redis = rg_crypto_buf_decrypt(str_2, strlen(str_2), 'c');
                            if(dec_redis == NULL){
                                pthread_mutex_unlock(&rg_wds_crypt_mtx);
                            } else {
                                strcpy(str_6,dec_redis);
                                rg_crypto_buf_free(dec_redis);
                                pthread_mutex_unlock(&rg_wds_crypt_mtx);
                                
                                //GPIO_DEBUG("redis pwd decrypto:%s",dec_redis);
                                if(strcmp(str_6,EWEB_DEF_PW_DC) != 0){
                                    strcpy(str,redis_wds_info->passwd);
                                    GPIO_DEBUG("sync ap pwd:%s",str);
                                    rg_wds_misc_write_file(EWEB_PW_FILE,str,strlen(str));
                                }
                            }
                            strcpy(str_3,redis_wds_info->networkid);
                            strcpy(str_4,redis_wds_info->networkname);
                            //GPIO_DEBUG("----------> sn:%s,id:%s,name:%s,pwd:%s,enc:%s",redis_wds_info->sn,str_3,str_4,dec_redis,str);
                        } else {
                             GPIO_DEBUG("redis get AP fail");
                             b_pw_flag = false;
                        }
                    } else {
                        GPIO_DEBUG("redis get CPE self fail");
                        b_pw_flag = false;
                    }
                    free(redis_wds_info);
                }
            }
        }
    }
#endif
    p = rg_wds_info_item_str("passwd",str,p);
    p = rg_wds_info_item_filter(p);

    memset(str_2,0,sizeof(str_2));
    rg_wds_json_first("/etc/rg_config/networkid.json","networkName",str_2,sizeof(str_2));
    if (strlen(str_2) == 0) {
        strcpy(str_2,"default");
    }
    
    p = rg_wds_info_item_str("networkName",str_2,p);
    p = rg_wds_info_item_filter(p);

	memset(str,0,sizeof(str));
	rg_wds_json_first("/etc/rg_config/networkid.json","networkId",str,sizeof(str)); //coredump
	if (strlen(str) == 0) {
		strcpy(str,"0");
	}
    
#ifdef EST_SUPPORT_REDIS 
    if (rg_ath_info_t.role == MODE_CPE && redis_wds_info != NULL && strlen(str_3) > 0 && strlen(str_4) > 0){
        if((strcmp(str,"0") == 0 && strcmp(str,str_3) != 0) || b_pw_flag == true){
            if(strcmp(str,str_3) != 0){
                strcpy(str,str_3);
                GPIO_DEBUG("networkid:%s",str);
                rg_wds_first_set("/etc/rg_config/networkid.json","networkId",str);
            }
            if(strcmp(str_2,str_4) != 0){
                strcpy(str_2,str_4);
                GPIO_DEBUG("networkname:%s",str_2);
                rg_wds_first_set("/etc/rg_config/networkid.json","networkName",str_2);
                p = rg_wds_info_item_str("networkName",str_2,p);
                p = rg_wds_info_item_filter(p);
            }
        }
    }
#endif
	p = rg_wds_info_item_str("networkId",str,p);
	p = rg_wds_info_item_filter(p);

	/*zhaoshuaibing add for country code 2020.6.15*/
	memset(str, 0, sizeof(str));
	memset(str_2, 0, sizeof(str_2));
	sprintf(str, CMD_GET_COUNTYCODE, rg_dev_capacity_table.wifi_name);
    rg_wds_uci_get_param(str,str_2,sizeof(str_2));
	GPIO_DEBUG("CMD_GET_COUNTYCODE:%s=%s", str, str_2);
    p = rg_wds_info_item_str("country",str_2,p);
    p = rg_wds_info_item_filter(p);

	memset(str, 0, sizeof(str));
	bool wds_pwstate = get_arr_wds_pwstat(KEYERR_TYPE_80211);
	GPIO_DEBUG("connstat  wdspw_state:%d",  wds_pwstate);
	sprintf(str, "%d", wds_pwstate);
	p = rg_wds_info_item_str("wdspw_state",str,p);
	p = rg_wds_info_item_filter(p);
	if (wds_pwstate == false){
		memset(str, 0, sizeof(str));
		get_wds_pw_arr_mac(str, 0, KEYERR_TYPE_80211);//获取密码错误的设备mac
		GPIO_DEBUG("wds pw error mac:%s",  str);
		p = rg_wds_info_item_str("warn_mac",str,p);
		p = rg_wds_info_item_filter(p);
	}
	
	memset(str, 0, sizeof(str));
	p = rg_wds_info_item_str("scan_dev_cap", rg_dev_capacity_table.scan_dev_cap, p);
	p = rg_wds_info_item_filter(p);
	
	wds_pwstate = get_arr_wds_pwstat(KEYERR_TYPE_CUSTOM);
	GPIO_DEBUG("connstat  wdspw_state:%d",  wds_pwstate);
	sprintf(str, "%d", wds_pwstate);
	p = rg_wds_info_item_str("scan_pw_state",str,p);
	p = rg_wds_info_item_filter(p);
	
	if (wds_pwstate == false){
		memset(str, 0, sizeof(str));
		get_wds_pw_arr_mac(str, 0, KEYERR_TYPE_CUSTOM);//获取密码错误的设备mac
		GPIO_DEBUG("wds pw error mac:%s",  str);
		p = rg_wds_info_item_str("scan_warn_mac",str,p);
		p = rg_wds_info_item_filter(p);
	}
	
    /*zhaoshuaibing add for country code 2020.9.3*/
    if (is_dfs_json_exist()) {
        memset(str, 0, sizeof(str));
        rg_wds_json_first("/etc/rg_config/dfs_json", "channel", str, sizeof(str));
        if (strlen(str) == 0) {
    		strcpy(str,"0");
    	}
        p = rg_wds_info_item_str("dch", str, p);
        p = rg_wds_info_item_filter(p);
        memset(str, 0, sizeof(str));
        rg_wds_json_first("/etc/rg_config/dfs_json", "time", str, sizeof(str));
         if (strlen(str) == 0) {
    		strcpy(str,"0");
    	}
        p = rg_wds_info_item_str("dtm", str, p);
        p = rg_wds_info_item_filter(p);
    }


    memset(str, 0, sizeof(str));
    memset(str_2, 0, sizeof(str_2));
    sprintf(str,CMD_GET_MANAGE_SSID,rg_dev_capacity_table.mag_ifname);
    rg_wds_uci_get_param(str,str_2,sizeof(str_2)); 
	GPIO_DEBUG("manage_ssid:%s", str_2);
    p = rg_wds_info_item_str("manage_ssid", str_2, p);
    p = rg_wds_info_item_filter(p);

    memset(str, 0, sizeof(str));
    memset(str_2, 0, sizeof(str_2));
    sprintf(str,CMD_GET_MANAGE_BSSID,rg_dev_capacity_table.mag_ifname);
    rg_wds_misc_cmd(str,str_2,sizeof(str_2));

    memset(str, 0, sizeof(str));
    strncpy(str,str_2,17);
    p = rg_wds_info_item_str("manage_bssid", str, p);
    p = rg_wds_info_item_filter(p);

    memset(str, 0, sizeof(str));
    bool dc_power_support;
    if (rg_dev_capacity_table.dc_power == 1) {
        dc_power_support = true;
    } else {
        dc_power_support = false;
    }
	sprintf(str, "%d", dc_power_support);
	p = rg_wds_info_item_str("dc_power",str,p);
	p = rg_wds_info_item_filter(p);

    memset(str, 0, sizeof(str));
    bool poe_power_support;
    if (rg_dev_capacity_table.poe_power == 1) {
        poe_power_support = true;
    } else {
        poe_power_support = false;
    }
	sprintf(str, "%d", poe_power_support);
	p = rg_wds_info_item_str("poe_power",str,p);
	p = rg_wds_info_item_filter(p);

	memset(str, 0, sizeof(str));
	sprintf(str, "%d", rg_dev_capacity_table.distance_max);
	p = rg_wds_info_item_str("distance_max",str,p);
	p = rg_wds_info_item_filter(p);
	
	memset(str, 0, sizeof(str));
	sprintf(str, "%d", rg_dev_capacity_table.distance_def);
	p = rg_wds_info_item_str("distance_def",str,p);
	p = rg_wds_info_item_filter(p);

    memset(str, 0, sizeof(str));
	sprintf(str, "%d", rg_dev_capacity_table.automatic_range);
	p = rg_wds_info_item_str("automatic_range",str,p);
	p = rg_wds_info_item_filter(p);

	memset(str, 0, sizeof(str));
	sprintf(str, "%d", rg_dev_capacity_table.wan_speed);
	p = rg_wds_info_item_str("wan_speed", str, p);
	p = rg_wds_info_item_filter(p);

	//AP have the ability to scan dev,CPE has the ability to be scanned
	p = rg_wds_info_item_str("scan_dev_cap", rg_dev_capacity_table.scan_dev_cap, p);//
	p = rg_wds_info_item_filter(p);
    GPIO_DEBUG("scan_dev_cap:%s",rg_dev_capacity_table.scan_dev_cap);

    memset(str, 0, sizeof(str));
    bool rssi_align_support;
    if (rg_dev_capacity_table.rssi_align == 1) {
        rssi_align_support = true;
    } else {
        rssi_align_support = false;
    }
	sprintf(str, "%d", rssi_align_support);
	p = rg_wds_info_item_str("rssi_align",str,p);
	p = rg_wds_info_item_filter(p);
    GPIO_DEBUG("rssi_align:%d",rg_dev_capacity_table.rssi_align);
    GPIO_DEBUG("==========>>end get info body");
    return p;
}

void rg_wds_send_info(char *buf) {
    char *p = buf;

    p = rg_wds_to_set_begin(p);
    p = rg_wds_to_dev_head(TYPE_INFO,"all",p);
    p = rg_wds_info_body(p);
    p = rg_wds_to_set_end(p);
    
    GPIO_DEBUG("buf %s len %d",buf,strlen(buf));
}

void crypto_get_pwd(char *pwd)
{
    char confuse[PWDLEN];

    strcat(pwd, PWDF);
    memset(confuse, 0, PWDLEN);
    strcat(confuse, PWDFALSE1);
    strcat(pwd, PWDS);
    memset(confuse, 0, PWDLEN);
    strcat(confuse, PWDFALSE2);
    strcat(pwd, PWDT);
}

unsigned char *printf_md5_str(unsigned char *md)
{
    int i;
	unsigned char md5_str[MD5_DIGEST_LENGTH*3];
	
    if (md == NULL) {
        return;
    }
    for (i = 0; i < MD5_DIGEST_LENGTH; i++){
        // GPIO_DEBUG("md:%02x", md[i]);
		snprintf(md5_str + i*2, 2+1, "%02x", md[i]);
    }
	GPIO_DEBUG("MD5 encrypted string:%s,%d", md5_str, strlen(md5_str));
	return md5_str;
}

unsigned char *md5_coding(char *data)
{
    int i;
    MD5_CTX c;
    char pwd[PWDLEN];
    static unsigned char md[MD5_DIGEST_LENGTH+1];
    //static unsigned char buf[BUFSIZE];
	static unsigned char dest_str[512];
    memset(pwd, 0, PWDLEN);
    crypto_get_pwd(pwd);

    /* read string form original_data buf */
    MD5_Init(&c);
    /* add the key before the coding string */
    MD5_Update(&c, (unsigned char *)pwd, strlen(pwd));
	/* add the coding string */
    MD5_Update(&c, data, strlen(data));
    MD5_Final(&(md[0]), &c);	
   	//print_md(md);
	return printf_md5_str(md);
}


int  rg_wds_send_info_crypto(char *buf, char *uncrypto_buf ) {
    char *p = buf;
    char *p_encrypto_buf = NULL;
    char *data_part = NULL;
    char encrypto_buf[EN_CRYPTO_PART_LEN];
	char encrypto_tmp_buf[2048];
	unsigned char *md5buf;
    int i = 0;
    int ret = 0;

    p = rg_wds_to_set_begin(p);
    p = rg_wds_to_dev_head(TYPE_CRYPTO,"all",p);
    data_part = malloc(UN_CRYPTO_PART_LEN);
    if (data_part == NULL) {
        goto end;
    }
    memset(uncrypto_buf, 0, UN_CRYPTO_LEN);
    rg_wds_info_body(uncrypto_buf);
    GPIO_DEBUG("uncrypto len:%d buf:%s", strlen(uncrypto_buf), uncrypto_buf);
    
    int uncrypto_len = strlen(uncrypto_buf);
    int crypto_times = (uncrypto_len + UN_CRYPTO_PART_LEN - 1) / UN_CRYPTO_PART_LEN;  // 计算需要加密的次数

    memset(encrypto_tmp_buf, 0, 2048);	
    for (i = 0; i < crypto_times; i++) {
        int start_index = i * (UN_CRYPTO_PART_LEN - 1);
        int end_index = start_index + UN_CRYPTO_PART_LEN - 1;
        if (end_index > uncrypto_len) {
            end_index = uncrypto_len;
        }
        int part_len = end_index - start_index;

        memset(data_part, 0, UN_CRYPTO_PART_LEN);
        memset(encrypto_buf, 0, EN_CRYPTO_PART_LEN);
        strncpy(data_part, uncrypto_buf + start_index, part_len);
        pthread_mutex_lock(&rg_wds_crypt_mtx);
        p_encrypto_buf = rg_crypto_buf_encrypt(data_part, strlen(data_part), 'c');
        if (p_encrypto_buf != NULL) {
            strcpy(encrypto_buf,p_encrypto_buf);
            rg_crypto_buf_free(p_encrypto_buf);   /* 释放内存 */
            p_encrypto_buf = NULL;
	        pthread_mutex_unlock(&rg_wds_crypt_mtx);
            
            GPIO_DEBUG("encrypto_buf %d len:%d:\n%s", i, strlen(encrypto_buf), encrypto_buf);
			strcat(encrypto_buf, CRYPTO_SPLIT_FLAG);
			strcat(buf, encrypto_buf);
            strcat(encrypto_tmp_buf, encrypto_buf);
            p += strlen(encrypto_buf);
        } else {
	        pthread_mutex_unlock(&rg_wds_crypt_mtx);
            ret = -1;
            goto end;
        }  
    }
    md5buf = md5_coding(encrypto_tmp_buf);
	strcat(md5buf, CRYPTO_SPLIT_FLAG);
	strcat(buf, md5buf);
    GPIO_DEBUG("------------->send crypto info len:%d buf:\n%s", strlen(buf), buf);
    
end:
    if (data_part != NULL) {
        free(data_part);
    }
    if(ret < 0) {
        return ret;
    }else{
        return strlen(buf);
    }
}

void rg_wds_send_all() {
    struct mac_ip_udp_wds_packet eth_heap_p;
    char *buf = NULL;
    int len = 0;

    buf = malloc(UN_CRYPTO_LEN);
    if (buf == NULL) {
        goto end;
    }

    memset(buf,0,UN_CRYPTO_LEN);
    memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
    rg_wds_send_date_head_init(&eth_heap_p);

	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
    len += sizeof(struct mac_ip_udp_wds_packet);

    rg_wds_send_info(buf + len);
    len = len + strlen(len + buf);

	rg_send_raw_date_2("br-wan",len,buf,NULL);
    //rg_wds_message_dev_process(buf + sizeof(struct mac_ip_udp_wds_packet));
end:
    if (buf != NULL) {
        free(buf);
    }

}

void rg_wds_send_all_crypto() {
    struct mac_ip_udp_wds_packet eth_heap_p;

    char *buf = NULL;
    char *uncrypto_buf = NULL;
    int len = 0;
    int data_len = 0;
    int i = 0;
    char *send_buf = NULL;
    memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
    rg_wds_send_date_head_init(&eth_heap_p);

    buf = malloc(EN_CRYPTO_LEN);
    if (buf == NULL) {
        goto end2;
    }

    uncrypto_buf = malloc(UN_CRYPTO_LEN);
    if (uncrypto_buf == NULL) {
        goto end2;
    }
    
    send_buf = malloc(MTU_DATA_LEN + sizeof(struct mac_ip_udp_wds_packet));
    if (send_buf == NULL) {
        goto end2;
    }
    
    memset(buf, 0, EN_CRYPTO_LEN);
    data_len = rg_wds_send_info_crypto(buf,uncrypto_buf);
    GPIO_DEBUG("send data crypto len:%d", data_len);
    if(data_len < 0) {
        GPIO_DEBUG("data crypto error");
        goto end1;
    }
    int segment_size = MTU_DATA_LEN-1;
    int num_segments = (data_len + segment_size - 1) / segment_size;
    unsigned char flag = 0x00;
    unsigned char match = 0x00;
    
    static unsigned char udp_match = 0;
    udp_match ++;
    if(udp_match == 0){
        udp_match = 1;
    }
    for (i = 0; i < num_segments; i++) {
        int segment_start = i * segment_size;
        int segment_end = segment_start + segment_size;
        if (segment_end > data_len) {
            segment_end = data_len;
        }

        memset(send_buf, 0, MTU_DATA_LEN + sizeof(struct mac_ip_udp_wds_packet));
        memcpy(send_buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
        len = segment_end - segment_start;
        memcpy(send_buf+sizeof(struct mac_ip_udp_wds_packet),buf + segment_start,len);
        if(i == 0) {
            flag = 0x55;//首包类型
            if(num_segments == 1){
                match = 0x00;
            } else {
                match = udp_match;
            }
        }
        //GPIO_DEBUG("cut data len:%d,buf:%s", len,send_buf + sizeof(struct mac_ip_udp_wds_packet));
        GPIO_DEBUG("---------> flag:%x,match:%d", flag,match);
        rg_send_raw_date_3("br-wan", len + sizeof(struct mac_ip_udp_wds_packet), send_buf, NULL, flag, match);
        flag = 0xaa;//尾包类型
    }
end1:
    memset(buf, 0, EN_CRYPTO_LEN);
    char *p = buf;
    p = rg_wds_to_set_begin(p);
    p = rg_wds_to_dev_head(TYPE_INFO,"all",p);
    memcpy(p,uncrypto_buf,strlen(uncrypto_buf));
    p = p+strlen(uncrypto_buf);
    p = rg_wds_to_set_end(p);
    GPIO_DEBUG("send to self no need crypto");
    rg_wds_message_dev_process(buf,true);
end2:
    if (buf != NULL) {
        free(buf);
    }
    if (uncrypto_buf != NULL) {
        free(uncrypto_buf);
    }
    if (send_buf != NULL) {
        free(send_buf);
    }
}

void rg_wds_status_check() {
    struct sysinfo info;
	//获取当前时间
	sysinfo(&info);

    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
	struct dev_multi_info *last_p = NULL;

    while(p) {
        if (info.uptime > p->time_update) {
            if ((info.uptime - p->time_update) > 5*60) {
                GPIO_DEBUG("sn %s unkonw %s time_update %d info.uptime %d ",
					                                                p->sn,
					                                               p->ssid,
					                                        p->time_update,
					                                            info.uptime);
				//非本机链表
				if (strcmp(p->sn,rg_dev_info_t.sn) != 0) {
                #ifdef EST_SUPPORT_REDIS
                    GPIO_DEBUG("DEL REDBS INFO AND TIPC TABLE:%s",p->sn);
                    redbs_wds_info_del_pub(p->sn);
                    redbs_wds_tipc_del_pub(p->sys_mac);
                #endif
                    g_dev_multi_info_cnt--;
					if (p == rg_wds_all_info) {
						rg_wds_all_info = p->next;
						free(p);
					} else if (p->next == NULL) {
						last_p->next = NULL;
						free(p);
					} else {
						last_p->next = p->next;
						free(p);
					}
					goto end;
				}

            }
        }
		last_p = p;
        p = p->next;
    }
end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_clear_all_list(){
    pthread_mutex_lock(&mtx_rg_wds_all_info);

    struct dev_multi_info *p = rg_wds_all_info;
    struct dev_multi_info *tmp;
    int len = 0;
    while(p) {
        tmp = p;
        p = p->next;
        len++;
        free(tmp);
        GPIO_DEBUG("free 11");
    }
    g_dev_multi_info_cnt = 0;

	rg_wds_all_info = NULL;
    GPIO_DEBUG("len %d",len);
#ifdef EST_SUPPORT_REDIS
    GPIO_DEBUG("REDBS CLEAN ALL");
    system("redis-cli -p 6380 flushall");
#endif
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

static bool is_set_hostname_networkid(void){
    if (access(NETWORKID_FILE_PATH, F_OK)==0){
        GPIO_DEBUG("%s file exist.", NETWORKID_FILE_PATH);
        if (remove(NETWORKID_FILE_PATH)!=0) {
            GPIO_DEBUG("remove %s failed!!!", NETWORKID_FILE_PATH);
        }
        return true;
    }
    return false;
}

void rg_wds_send_multi(unsigned long time_count_all) {
    if (is_set_hostname_networkid()) {
        rg_wds_dev_update(&rg_dev_info_t);
        if(g_count_down > 0){
            rg_wds_send_all();
        }
        rg_wds_send_all_crypto();
        rg_wds_status_check();
        //rg_wds_write_info_all_list();
        //rg_wds_wrt_info_lite();
        return;
    }
    if (time_count_all % 100 == 99 && g_count_down > 0) {
        rg_wds_send_all();
        //每10秒次发送一次，并开始倒计时5分钟
        g_count_down = g_count_down - 10;
    }
    
    if (time_count_all % 100 == 88) {
        rg_wds_send_all_crypto();
    }

    //每10
    if (time_count_all % (10 * 10)== 60) {
        rg_wds_status_check();
    }

    if (time_count_all % 100 == 49) {
//        rg_wds_wrt_wdsall_page();
        //rg_wds_write_info_all_list();
        //rg_wds_wrt_info_lite();
    }
}

void broadcast_pkt_send_pthread(void) {
    while(1){
        sleep(5);
        if (is_set_hostname_networkid()) {
            rg_wds_dev_update(&rg_dev_info_t);
            if(g_count_down > 0){
                rg_wds_send_all();
            }
            rg_wds_send_all_crypto();
            rg_wds_status_check();
            continue;
        }
        
        if (g_count_down > 0) {
            rg_wds_send_all();
            g_count_down = g_count_down - 10;
        }
        
        rg_wds_send_all_crypto();
        sleep(5);
        rg_wds_status_check();
        }
}

char *rg_wds_get_option_vaule(char *buf,char *option,int op_len,char *value,int va_len){
    char *p = buf;
    int i = 0;
    int j;

    if (strlen(buf) < 2) {
        return NULL;
    }

    memset(option,0,op_len);
    memset(value,0,va_len);

    while(1) {
        if (p[i] == ':' || p[i] == 0) {
            break;
        }
        i++;
    }

    if (i > 0) {
        memcpy(option,p,i);
        //DEBUG("option %s,i %d",option,i);
    } else {
        goto end;
    }


    j = i;
    while(1) {
        if (p[i] == ';' || p[i] == 0 ||  p[i] == '#') {
            break;
        }
        i++;
    }
    if (i - j - 1 > 0) {
        memcpy(value,buf + j + 1,i - j - 1);
        //DEBUG("value %s,i %d",value,i - j - 1);
    } else {
        goto end;
    }

    //GPIO_DEBUG("%s:%s",option,value);
    return p + i + 1;

end:
    return NULL;
}

struct dev_multi_info * rg_wds_get_info_all_list(struct dev_multi_info *data) {
    //pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    struct dev_multi_info *tmp;
    struct dev_multi_info *p1;
    p1 = p;
    while (p != NULL) {
        if (strcmp(p->sn,data->sn) == 0) {
            //memcpy(p->sn ,data->sn,sizeof(data->sn));
            p->time_update = data->time_update;
            //memcpy(p->time_update ,data->time_update,sizeof(data->time_update));
            if(strlen(data->peer_sn) > 0 ){strcpy(p->peer_sn , data->peer_sn);}
            if(strlen(data->sys_mac) > 0 ){strcpy(p->sys_mac ,data->sys_mac);}
            if(strlen(data->ath_mac) > 0 ){strcpy(p->ath_mac ,data->ath_mac);}
            if(strlen(data->peermac) > 0 ){strcpy(p->peermac ,data->peermac);}
            if(strlen(data->dev_type) > 0 ){strcpy(p->dev_type , data->dev_type);}
        	if(strlen(data->ipaddr) > 0 ){strcpy(p->ipaddr ,data->ipaddr);}
            if(strlen(data->netmask) > 0 ){strcpy(p->netmask , data->netmask);}
            if(strlen(data->time) > 0 ){strcpy(p->time ,data->time);}
            if(strlen(data->band) > 0 ){strcpy(p->band ,data->band);}
            if(strlen(data->rssi) > 0 ){strcpy(p->rssi , data->rssi);}
            if(strlen(data->rssi_a) > 0 ){strcpy(p->rssi_a , data->rssi_a);}
            if(strlen(data->rate) > 0 ){strcpy(p->rate , data->rate);}
            if(strlen(data->channel) > 0 ){strcpy(p->channel , data->channel);}
            if(strlen(data->passwd) > 0 ){strcpy(p->passwd , data->passwd);}
            if(strlen(data->channf) > 0 ){strcpy(p->channf , data->channf);}
            if(strlen(data->chutil) > 0 ){strcpy(p->chutil ,data->chutil);}
            if(strlen(data->chutil_a) > 0 ){strcpy(p->chutil_a ,data->chutil_a);}
            if(strlen(data->phymode) > 0 ){strcpy(p->phymode ,data->phymode);}
        	if(strlen(data->host_name) > 0 ){strcpy(p->host_name , data->host_name);}
            if(strlen(data->role) > 0 ){strcpy(p->role , data->role);}
            if(strlen(data->lock) > 0 ){strcpy(p->lock , data->lock);}
            if(strlen(data->onlinestatus) > 0 ){strcpy(p->onlinestatus , data->onlinestatus);}
            if(strlen(data->cwmp) > 0 ){strcpy(p->cwmp , data->cwmp);}
            if(strlen(data->lan1speed) > 0 ){strcpy(p->lan1speed , data->lan1speed);}
            if(strlen(data->lan1link) > 0 ){strcpy(p->lan1link , data->lan1link);}
            if(strlen(data->lan1duplex) > 0 ){strcpy(p->lan1duplex , data->lan1duplex);}
        	if(strlen(data->lan1nosupport) > 0 ){strcpy(p->lan1nosupport ,data->lan1nosupport);}
            if(strlen(data->lan2speed) > 0 ){strcpy(p->lan2speed , data->lan2speed);}
            if(strlen(data->lan2link) > 0 ){strcpy(p->lan2link , data->lan2link);}
            if(strlen(data->lan2duplex) > 0 ){strcpy(p->lan2duplex , data->lan2duplex);}
        	if(strlen(data->lan2nosupport) > 0 ){strcpy(p->lan2nosupport , data->lan2nosupport);}
            if(strlen(data->rx_rate) > 0 ){strcpy(p->rx_rate ,data->rx_rate);}
            if(strlen(data->tx_rate) > 0 ){strcpy(p->tx_rate , data->tx_rate);}
            if(strlen(data->rx_speed) > 0 ){strcpy(p->rx_speed ,data->rx_speed);}
            if(strlen(data->tx_speed) > 0 ){strcpy(p->tx_speed , data->tx_speed);}
            if(strlen(data->rx_speed_a) > 0 ){strcpy(p->rx_speed_a , data->rx_speed_a);}
            if(strlen(data->tx_speed_a) > 0 ){strcpy(p->tx_speed_a ,data->tx_speed_a);}
            if(strlen(data->ssid) > 0 ){strcpy(p->ssid ,data->ssid);}
            if(strlen(data->software_version) > 0 ){strcpy(p->software_version , data->software_version);}
        	if(strlen(data->softver_new) > 0 ){strcpy(p->softver_new , data->softver_new);}
        	if(strlen(data->clean_sftn) > 0 ){strcpy(p->clean_sftn ,data->clean_sftn);}
            if(strlen(data->hardware_version) > 0 ){strcpy(p->hardware_version , data->hardware_version);}
        	if(strlen(data->wds_tpye) > 0 ){strcpy(p->wds_tpye , data->wds_tpye);}
            if(strlen(data->wds_distance) > 0 ){strcpy(p->wds_distance , data->wds_distance);}
            if(strlen(data->wds_txpower) > 0 ){strcpy(p->wds_txpower ,data->wds_txpower);}
            p->nf = data->nf;                    
            p->channel_use = data->channel_use;
            if(strlen(data->pingTime) > 0 ){strcpy(p->pingTime , data->pingTime);}
            if(strlen(data->connectTime) > 0){strcpy(p->connectTime , data->connectTime);}
            if(strlen(data->networkid) > 0 ){strcpy(p->networkid , data->networkid);}
            if(strlen(data->networkname) > 0 ){strcpy(p->networkname ,data->networkname);}
        	if(strlen(data->country) > 0 ){strcpy(p->country , data->country);}
            p->flag = data->flag;
            p->dfs_ch = data->dfs_ch;    
            if(strlen(data->dfs_time) > 0 ){strcpy(p->dfs_time , data->dfs_time);  }
            if(strlen(data->def_pw) > 0 ){strcpy(p->def_pw ,data->def_pw);    }     
            if(strlen(data->wds_pw) > 0 ){strcpy(p->wds_pw , data->wds_pw);   }     
            if(strlen(data->wdspw_state) > 0 ){strcpy(p->wdspw_state , data->wdspw_state);  } 
            if(strlen(data->warn_mac) > 0 ){strcpy(p->warn_mac ,data->warn_mac);   }  
        	if(strlen(data->scan_dev_cap) > 0 ){strcpy(p->scan_dev_cap , data->scan_dev_cap);}
        	if(strlen(data->scan_pw_state) > 0 ){strcpy(p->scan_pw_state , data->scan_pw_state);}
            if(strlen(data->scan_warn_mac) > 0 ){strcpy(p->scan_warn_mac ,data->scan_warn_mac);}
            if(strlen(data->manage_ssid) > 0 ){strcpy(p->manage_ssid , data->manage_ssid);}
            if(strlen(data->manage_bssid) > 0 ){strcpy(p->manage_bssid , data->manage_bssid);  }
            if(strlen(data->dc_power) > 0 ){strcpy(p->dc_power , data->dc_power);}
            if(strlen(data->poe_power) > 0 ){strcpy(p->poe_power ,data->poe_power); }       
            if(strlen(data->distance_max) > 0 ){strcpy(p->distance_max , data->distance_max);}
        	if(strlen(data->distance_def) > 0 ){strcpy(p->distance_def ,data->distance_def);}
        	if(strlen(data->automatic_range) > 0 ){strcpy(p->automatic_range , data->automatic_range);}
        	if(strlen(data->wan_speed_cap) > 0 ){strcpy(p->wan_speed_cap , data->wan_speed_cap);}
            if(strlen(data->rssi_align) > 0 ){strcpy(p->rssi_align ,data->rssi_align);   } 
            goto end;
        }
        p1 = p;
        p = p->next;
    }

    if (p == NULL && g_dev_multi_info_cnt < DEV_MULTI_MAXCNT) {
        tmp = malloc(sizeof(struct dev_multi_info));
        GPIO_DEBUG("create dev_multi_info node:%s",data->sn);
        if (tmp != NULL) {
            memset(tmp,0,sizeof(struct dev_multi_info));
            //memcpy(tmp->sn,data->sn,strlen(data->sn));
            memcpy(tmp,data,sizeof(struct dev_multi_info));
            tmp->time_update = data->time_update;
            tmp->next = NULL;
            p = tmp;
            g_dev_multi_info_cnt++;
        }
        if (rg_wds_all_info == NULL) {
            rg_wds_all_info = tmp;
        } else {
            p1->next = tmp;
        }
    }
end:
    //pthread_mutex_unlock(&mtx_rg_wds_all_info);
    return p;
}

void rg_wds_show_info_all_list() {
    return;
    struct dev_multi_info *p = rg_wds_all_info;
    while (p != NULL) {
        DEBUG("sn:%s",p->sn);
        DEBUG("sys_mac:%s",p->sys_mac);
        DEBUG("ath_mac:%s",p->ath_mac);
        DEBUG("lock:%s",p->lock);
        DEBUG("role:%s",p->role);
        DEBUG("ssid:%s",p->ssid);
        DEBUG("dev_type:%s",p->dev_type);
        DEBUG("software_version:%s",p->software_version);
        DEBUG("peer_sn:%s",p->peer_sn);
        DEBUG("ip:%s",p->ipaddr);
        p = p->next;
    }
}



struct dev_multi_info * rg_wds_find_peer(struct dev_multi_info *p,char *peer_sn) {
	//GPIO_DEBUG("wwwwwwww out mac:%s len:%d, in athmac:%s len:%d", peer_sn, strlen(peer_sn), p->ath_mac, strlen( p->ath_mac));
    while (p) {
		if (strlen(peer_sn) !=0) {
	        if ((strcmp(peer_sn,p->ath_mac) == 0 || strcmp(peer_sn,p->peermac) == 0) && p->flag == 0) {
				//GPIO_DEBUG("wwwwwwww out while() athmac:%s in athmac:%s in peermac:%s", peer_sn, p->ath_mac, p->peermac);
	            p->flag = 1;
	            return p;
	        }
		}
        p = p->next;
    }
    return p;
}

void str_split_to_json_arr(json_object *j_array, char *arr_name, char *src, const char *delim){
	char tmp[(STR_MAC_SIZE-1)*WDS_PW_INFO_ARR_LEN+(WDS_PW_INFO_ARR_LEN-1)+1];
	char *token;
	
	memset(tmp, 0, sizeof(tmp));
	strncpy(tmp, src, sizeof(tmp));
	
   	token = strtok(tmp, delim);
   
	while( token != NULL ) {
		json_object_array_add(j_array,json_object_new_string(token));
		token = strtok(NULL, delim);
	}
	
}

void rg_wds_json_add_item(struct dev_multi_info *p,json_object *item, json_object *j_array) {
    char tmp[64];
	json_object *arr,*scanPwWarnMac;
    json_object_object_add(item,"sn", json_object_new_string(p->sn));
    json_object_object_add(item,"mac", json_object_new_string(p->sys_mac));
    json_object_object_add(item,"ssid", json_object_new_string(p->ssid));
	memset(tmp, 0, sizeof(tmp));
	if(strcmp(p->softver_new, "clean")==0 || strcmp(p->clean_sftn, "1")==0){ //收到的softver_new为clean的R221版本或者clean_sftn为1的R96.2版本，说明需要清空sofver_new中残留的ReyeeOS,不再有ReyeeOS版本号。
		memset(p->softver_new, 0, sizeof(p->softver_new));
	}
	//兼容qca旧版本，当没有ReyeeOS 1.58.1912时和以前一样。
	if(strlen(p->softver_new) !=0 ){
		strcat(tmp, p->softver_new);
		strcat(tmp, ";");
	}
	strcat(tmp, p->software_version);
    json_object_object_add(item,"softversion", json_object_new_string(tmp));
    json_object_object_add(item,"role", json_object_new_string(p->role));
    json_object_object_add(item,"userIp", json_object_new_string(p->ipaddr));
    json_object_object_add(item,"peersn", json_object_new_string(p->peer_sn));
    json_object_object_add(item,"userIp", json_object_new_string(p->ipaddr));
    json_object_object_add(item,"onlineTime", json_object_new_string(p->time));
    json_object_object_add(item,"band", json_object_new_string(p->band));
    json_object_object_add(item,"rssi", json_object_new_string(p->rssi));
    json_object_object_add(item,"rssi_a", json_object_new_string(p->rssi_a));
    json_object_object_add(item,"rxrate", json_object_new_string(p->rate));
    json_object_object_add(item,"channel", json_object_new_string(p->channel));
    json_object_object_add(item,"passwd", json_object_new_string(p->passwd));
    json_object_object_add(item,"channf", json_object_new_string(p->channf));
    json_object_object_add(item,"chutil", json_object_new_string(p->chutil));
    json_object_object_add(item,"chutil_a", json_object_new_string(p->chutil_a));
    json_object_object_add(item,"distance", json_object_new_string(p->wds_distance));
    json_object_object_add(item,"txpower", json_object_new_string(p->wds_txpower));
    json_object_object_add(item,"phymode", json_object_new_string(p->phymode));
    json_object_object_add(item,"netmask", json_object_new_string(p->netmask));
    json_object_object_add(item,"lock", json_object_new_string(p->lock));
    json_object_object_add(item,"cwmp", json_object_new_string(p->cwmp));
    json_object_object_add(item,"lan1speed", json_object_new_string(p->lan1speed));
    json_object_object_add(item,"lan1link", json_object_new_string(p->lan1link));
    json_object_object_add(item,"lan1duplex", json_object_new_string(p->lan1duplex));
	json_object_object_add(item,"lan1nosupport", json_object_new_boolean(atoi(p->lan1nosupport)));
    json_object_object_add(item,"lan2speed", json_object_new_string(p->lan2speed));
    json_object_object_add(item,"lan2link", json_object_new_string(p->lan2link));
    json_object_object_add(item,"lan2duplex", json_object_new_string(p->lan2duplex));
	json_object_object_add(item,"lan2nosupport", json_object_new_boolean(atoi(p->lan2nosupport)));
    json_object_object_add(item,"hostname", json_object_new_string(p->host_name));
    json_object_object_add(item,"onlinestatus", json_object_new_string(p->onlinestatus));
    json_object_object_add(item,"rx_rate", json_object_new_string(p->rx_rate));
    json_object_object_add(item,"tx_rate", json_object_new_string(p->tx_rate));
    json_object_object_add(item,"dev_type", json_object_new_string(p->dev_type));
    json_object_object_add(item,"peermac", json_object_new_string(p->peermac));
    json_object_object_add(item,"athmac", json_object_new_string(p->ath_mac));
    json_object_object_add(item,"hardversion", json_object_new_string(p->hardware_version));
    json_object_object_add(item,"rx_speed", json_object_new_string(p->rx_speed));
    json_object_object_add(item,"tx_speed", json_object_new_string(p->tx_speed));
    json_object_object_add(item,"rx_speed_a", json_object_new_string(p->rx_speed_a));
    json_object_object_add(item,"tx_speed_a", json_object_new_string(p->tx_speed_a));
    json_object_object_add(item,"pingTime", json_object_new_string(p->pingTime));
    json_object_object_add(item,"connectTime", json_object_new_string(p->connectTime));

    json_object_object_add(item,"networkId", json_object_new_string(p->networkid));
    json_object_object_add(item,"networkName", json_object_new_string(p->networkname));

	json_object_object_add(item, "country", json_object_new_string(p->country));

    memset(tmp, 0, sizeof(tmp));
    sprintf(tmp, "%d", p->dfs_ch);
    json_object_object_add(item, "dch", json_object_new_string(tmp));
    json_object_object_add(item, "dtm", json_object_new_string(p->dfs_time));
	json_object_object_add(item, "def_pw", json_object_new_boolean(atoi(p->def_pw)));
	json_object_object_add(item, "wds_pw", json_object_new_boolean(atoi(p->wds_pw)));
	if(strlen(p->wdspw_state) == 0){
		sprintf(p->wdspw_state, "%s", "1");//兼容高通旧版本，没有这个信息，代表不支持，默认密码正确。
	}
	json_object_object_add(item, "wdspw_state", json_object_new_boolean(atoi(p->wdspw_state)));
	if(strcmp(p->wdspw_state,"1") == 0){
		GPIO_DEBUG("wdspw right clean warn_mac");
		memset(p->warn_mac, 0, sizeof(p->warn_mac));//当密码正确时清空warn_mac
	}
	json_object_object_add(item, "warn_mac", json_object_new_string(p->warn_mac));
    
	if(strlen(p->dc_power) == 0){
		sprintf(p->dc_power, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持dc供电。
	}
    json_object_object_add(item, "dc_power", json_object_new_boolean(atoi(p->dc_power)));
    
    if(strlen(p->poe_power) == 0){
		sprintf(p->poe_power, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持poe供电。
	}
    json_object_object_add(item, "poe_power", json_object_new_boolean(atoi(p->poe_power)));
    
	if(strlen(p->rssi_align) == 0){
		sprintf(p->rssi_align, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持rssi对准。
	}
    json_object_object_add(item, "rssi_align", json_object_new_boolean(atoi(p->rssi_align)));
    
	if(strlen(p->distance_max) == 0){
		sprintf(p->distance_max, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持从wds_list_all接口获取距离值。
	}
    json_object_object_add(item, "distance_max", json_object_new_string(p->distance_max));
	
	if(strlen(p->distance_def) == 0){
		sprintf(p->distance_def, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持从wds_list_all接口获取距离值。
	}
    json_object_object_add(item, "distance_def", json_object_new_string(p->distance_def));
	
	if(strlen(p->automatic_range) == 0){
		sprintf(p->automatic_range, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持自动测距(以前的设备都不支持自动测距)。
	}
    json_object_object_add(item, "automatic_range", json_object_new_boolean(atoi(p->automatic_range)));
	
	if(strlen(p->wan_speed_cap)== 0){
		memset(p->wan_speed_cap, 0, sizeof(p->wan_speed_cap));
		GPIO_DEBUG("sn:%s without wan_speed_cap def wanSpeedCap=100", p->sn);
		memcpy(p->wan_speed_cap, "100", 3); //兼容旧设备，没有接收wan_speed和原来保持一致100M
	}
	json_object_object_add(item, "wanSpeedCap", json_object_new_string(p->wan_speed_cap));

	json_object_object_add(item, "scanDevCap", json_object_new_boolean(atoi(p->scan_dev_cap)));
	if(strlen(p->scan_pw_state) == 0){
		sprintf(p->scan_pw_state, "%s", "1");//兼容R228以前的旧版本，没有这个信息，代表不支持，默认扫描密码正确。
	}
	json_object_object_add(item, "scanPwStat", json_object_new_boolean(atoi(p->scan_pw_state)));

	if(strcmp(p->scan_pw_state, "1")==0){
		GPIO_DEBUG("scan_pw_state right clean scan_warn_mac");
		memset(p->scan_warn_mac, 0, sizeof(p->scan_warn_mac));//当扫描设备密码正确时清空scan_warn_mac
	}
	
	if(strlen(p->scan_warn_mac)){
		str_split_to_json_arr(j_array, "scanPwWarnMac", p->scan_warn_mac, "-");
	}
	json_object_object_add(item, "scanPwWarnMac", j_array);
	json_object_object_add(item, "virtual", json_object_new_boolean(0));
	
}

void rg_wds_json_add_lite_item(struct dev_multi_info *p,json_object *item) {
    json_object_object_add(item,"sn", json_object_new_string(p->sn));
    json_object_object_add(item,"mac", json_object_new_string(p->sys_mac));//coredump
    json_object_object_add(item,"rl", json_object_new_string(p->role));
    json_object_object_add(item,"dt", json_object_new_string(p->dev_type));
    json_object_object_add(item,"nid", json_object_new_string(p->networkid));
    json_object_object_add(item,"nn", json_object_new_string(p->networkname));
    json_object_object_add(item,"rs", json_object_new_string(p->rssi));
    json_object_object_add(item,"ts", json_object_new_string(p->tx_speed));
    json_object_object_add(item,"hn", json_object_new_string(p->host_name));
    json_object_object_add(item,"ct", json_object_new_string(p->connectTime));
    json_object_object_add(item,"ch", json_object_new_string(p->channel));
	json_object_object_add(item, "def_pw", json_object_new_boolean(atoi(p->def_pw)));
	json_object_object_add(item, "wds_pw", json_object_new_boolean(atoi(p->wds_pw)));
	if(strlen(p->wdspw_state) == 0){
		sprintf(p->wdspw_state, "%d", "1");//兼容高通旧版本，没有这个信息，代表不支持，默认密码正确。
	}
	json_object_object_add(item, "wdspw_state", json_object_new_boolean(atoi(p->wdspw_state)));
	json_object_object_add(item, "warn_mac", json_object_new_string(p->warn_mac));
    json_object_object_add(item, "manage_ssid", json_object_new_string(p->manage_ssid));
	json_object_object_add(item, "manage_bssid", json_object_new_string(p->manage_bssid));
    if(strlen(p->dc_power) == 0){
		sprintf(p->dc_power, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持dc供电。
	}
    json_object_object_add(item, "dc_power", json_object_new_boolean(atoi(p->dc_power)));
    if(strlen(p->poe_power) == 0){
		sprintf(p->poe_power, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持poe供电。
	}
    json_object_object_add(item, "poe_power", json_object_new_boolean(atoi(p->poe_power)));

    if(strlen(p->rssi_align) == 0){
		sprintf(p->rssi_align, "%s", "0");//兼容旧版本，没有这个信息设置为0，0代表不支持rssi对准。
	}
    json_object_object_add(item, "rssi_align", json_object_new_boolean(atoi(p->rssi_align)));
}

static unsigned int rg_wds_get_page_size(void)
{
    struct dev_multi_info *p;
    unsigned int page_group;

    p = rg_wds_all_info;
    if (!p) {
        return 0;
    }

    page_group = 0;
    while (p) {
        /* cpe offline */
        if (strcmp("cpe", p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            } else {
                goto loop2;
            }
        }
loop1:
        page_group++;
loop2:
        p = p->next;
    }

    return page_group;
}

#if 0
void rg_wds_wrt_wdsall_page(void)
{
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    json_object *section, *section_1, *file_1, *file_2, *item_3, *item_4;
    unsigned int page_total, group_total, page_size, file_num;
    unsigned int total = 0;
    unsigned int wds_total[4];
    char wds_file_name[128], flag_free;
    const char *str;
    int fd;
    struct dev_multi_info *tmp = NULL;

    system("rm -rf /tmp/wds_all_page*.json");

    file_num = 0;
    group_total = rg_wds_get_page_size();
    if (group_total == 0) {
        pthread_mutex_unlock(&mtx_rg_wds_all_info);
        return;
    }

    page_size = group_total;
    file_1 = json_object_new_object();
    section = json_object_new_array();
    while (p) {
        total++;
        file_2 = json_object_new_object();
        section_1 = json_object_new_array();
        item_3 = json_object_new_object();
        flag_free = 0;
        if (p->flag == 0) {
            p->flag = 1;
        } else {
            flag_free = 1;
            goto loop2;
        }
        /* cpe offline */
        if (strcmp("cpe", p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            }
        }
loop1:
        tmp = rg_wds_all_info;
        while (tmp) {
            if (strcmp("ap", p->role) == 0) {
                tmp = rg_wds_find_peer(tmp, p->ath_mac);
            } else {
                tmp = rg_wds_find_peer(tmp, p->peermac);
            }
            if (tmp != NULL) {
                json_object *item_2 = json_object_new_object();
                rg_wds_json_add_item(tmp, item_2);
                 json_object_array_add(section_1, item_2);
                tmp = tmp->next;
            }
        }
        rg_wds_json_add_item(p, item_3);
        json_object_array_add(section_1, item_3);
        json_object_object_add(file_2, "list_pair", section_1);
        json_object_array_add(section, file_2);
        page_total++;
        page_size--;

        if (page_total % LIST_ALL_PAGE_SIZE == 0
            || (page_size < LIST_ALL_PAGE_SIZE && page_size % LIST_ALL_PAGE_SIZE == 0)) {
            file_num++;
            memset(wds_total, 0, sizeof(wds_total));
            snprintf(wds_total, sizeof(wds_total), "%u", group_total);
            json_object_object_add(file_1, "total", json_object_new_string(wds_total));
            json_object_object_add(file_1, "list_all", section);
            str = json_object_to_json_string(file_1);
            memset(wds_file_name, 0, sizeof(wds_file_name));
            snprintf(wds_file_name, sizeof(wds_file_name), "/tmp/wds_all_page_%d.json", file_num);
            rg_wds_misc_clear_file(wds_file_name);
            fd = open(wds_file_name, O_CREAT | O_RDWR, 0644);
            if (fd) {
                write(fd, str, strlen(str));
                close(fd);
            }

            json_object_put(file_1);

            file_1 = json_object_new_object();
            section = json_object_new_array();
        }
loop2:
        if (flag_free) {
            json_object_put(item_3);
            json_object_put(section_1);
            json_object_put(file_2);
        }
        p = p->next;
    }

    p = rg_wds_all_info;
    while (p) {
        p->flag = 0;
        p = p->next;
    }
    json_object_put(section);
    json_object_put(file_1);

end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
    return;
}
#endif
void rg_wds_write_info_all_list() {
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    unsigned int total = 0;
    unsigned int wds_total[4];

	if (p == NULL) {
		rg_wds_misc_clear_file("/tmp/wds_info_all.json");
		goto end;
	}

	json_object *file_1 = json_object_new_object();
	if (file_1 == NULL) {
		GPIO_ERROR("file_1 is NULL!!!");
		goto end;
	}
    json_object *section_2 = json_object_new_array();
	if (section_2 == NULL) {
		json_object_put(file_1); //Ensure that previously allocated memory space is freed
		GPIO_ERROR("section_2 is null!!!");
		goto end;
	}
    char flag_free = 0;

    while(p != NULL) {
        json_object *section_1 = json_object_new_array();
		if (section_1 == NULL) {
			GPIO_WARNING("section_1 is null !");
			continue; //Make sure the allocation is successful and move on
		}
        json_object *file_2 = json_object_new_object();
		if (file_2 == NULL) {
			json_object_put(section_1); //The successfully allocated memory is freed before proceeding to the next round
			GPIO_WARNING("file_2 is null !");
			continue; //Make sure the allocation is successful and move on
		}
        json_object *item_3 = json_object_new_object();
		if (item_3 == NULL) {
			json_object_put(section_1);//The successfully allocated memory is freed before proceeding to the next round
			json_object_put(file_2);
			GPIO_WARNING("item_3 is null !");
			continue; //Make sure the allocation is successful and move on
		}
		
		json_object *j_array3 = json_object_new_array();
		if (j_array3 == NULL) {
			json_object_put(section_1);//The successfully allocated memory is freed before proceeding to the next round
			json_object_put(file_2);
			json_object_put(item_3);
			GPIO_WARNING("j_array3 is null !");
			continue; //Make sure the allocation is successful and move on
		}
        flag_free = 0;
		
		/*rg_wds_all_info->flag is used to mark whether the JSON memory has been freed*/
        if (p->flag == 0) {
            p->flag = 1;
        } else {
            flag_free = 1;
            goto loop2;
        }

        //CPE有可能没有桥接成功的情况
        if (strcmp("cpe",p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            }
        }

        struct dev_multi_info *tmp = rg_wds_all_info;
        while (tmp) {
			struct dev_multi_info *index_tmp = tmp;
            if (strcmp("ap",p->role) == 0) {
                tmp = rg_wds_find_peer(tmp,p->ath_mac);
            } else {
                tmp = rg_wds_find_peer(tmp,p->peermac);
            }
            if (tmp != NULL) {
				//GPIO_DEBUG("wwwwwwww tmp->mac:%s ", tmp->ath_mac);
                json_object *item_2 = json_object_new_object();
				json_object *j_array2 = json_object_new_array();
				if (item_2==NULL) {
					if(j_array2){
						json_object_put(j_array2);
					}
					tmp = index_tmp; //Memory allocation fails. This node continues
					GPIO_WARNING("item_2 is null ! so continue alloc memory! ( sysmac [ %s ])", tmp->sys_mac);
					continue;//Make sure the allocation is successful and move on
				}
				if (j_array2==NULL) {
					json_object_put(item_2);
					tmp = index_tmp; //Memory allocation fails. This node continues
					GPIO_WARNING("j_array2 is null ! so continue alloc memory! ( sysmac [ %s ])", tmp->sys_mac);
					continue;//Make sure the allocation is successful and move on
				}
                rg_wds_json_add_item(tmp,item_2, j_array2);
                json_object_array_add(section_1, item_2);//coredump
                tmp = tmp->next;
            }
        }
loop1:
        rg_wds_json_add_item(p,item_3, j_array3);
        json_object_array_add(section_1, item_3);
        json_object_object_add(file_2, "list_pair", section_1);
        json_object_array_add(section_2, file_2);
loop2:
        if (flag_free) {
            json_object_put(section_1);
            json_object_put(file_2);
            json_object_put(item_3);
			json_object_put(j_array3);
        }
        p = p->next;
    }

    p = rg_wds_all_info;
    while (p) {
        p->flag = 0;
        p = p->next;
        total++;
    }

    json_object_object_add(file_1, "list_all", section_2);
    memset(wds_total, 0, sizeof(wds_total));
    snprintf(wds_total, sizeof(wds_total), "%u", total);
    json_object_object_add(file_1, "total", json_object_new_string(wds_total));

    int fd;
    const char *str = json_object_to_json_string(file_1); //coredump
    rg_wds_misc_clear_file("/tmp/wds_info_all.json");
	fd = open("/tmp/wds_info_all.json", O_CREAT | O_RDWR,0644);
    if (fd) {
        write(fd,str,strlen(str));
        close(fd);
    }

    json_object_put(file_1);
end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_wrt_info_lite() {
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    unsigned int total = 0;
    unsigned int wds_total[4];

	if (p == NULL) {
		rg_wds_misc_clear_file("/tmp/wds_info_lite.json");
		goto end;
	}

	json_object *file_1 = json_object_new_object();
	if (file_1 == NULL) {
		GPIO_ERROR("wrt_info_lite:file_1 is NULL!!!");
		goto end;
	}
    json_object *section_2 = json_object_new_array();
	if (section_2 == NULL) {
		json_object_put(file_1); //Ensure that previously allocated memory space is freed
		GPIO_ERROR("wrt_info_lite:section_2 is null!!!");
		goto end;
	}
    char flag_free = 0;

    while(p != NULL) {
        json_object *section_1 = json_object_new_array();
		if (section_1 == NULL) {
			GPIO_WARNING("wrt_info_lite:section_1 is null !");
			continue; //Make sure the allocation is successful and move on
		}
        json_object *file_2 = json_object_new_object();
		if (file_2 == NULL) {
			json_object_put(section_1); //The successfully allocated memory is freed before proceeding to the next round
			GPIO_WARNING("wrt_info_lite:file_2 is null !");
			continue; //Make sure the allocation is successful and move on
		}
        json_object *item_3 = json_object_new_object();
		if (item_3 == NULL) {
			json_object_put(section_1);//The successfully allocated memory is freed before proceeding to the next round
			json_object_put(file_2);
			GPIO_WARNING("wrt_info_lite:item_3 is null !");
			continue; //Make sure the allocation is successful and move on
		}
        flag_free = 0;
        if (p->flag == 0) {
            p->flag = 1;
        } else {
            flag_free = 1;
            goto loop2;
        }

        //CPE有可能没有桥接成功的情况
        if (strcmp("cpe",p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            }
        }

        struct dev_multi_info *tmp = rg_wds_all_info;
        while (tmp) {
			struct dev_multi_info * index_tmp = tmp;
            if (strcmp("ap",p->role) == 0) {
                tmp = rg_wds_find_peer(tmp,p->ath_mac);
            } else {
                tmp = rg_wds_find_peer(tmp,p->peermac);
            }
            if (tmp != NULL) {
                json_object *item_2 = json_object_new_object();
				if (item_2 == NULL) {
					tmp = index_tmp; //Memory allocation fails. This node continues
					GPIO_WARNING("wrt_info_lite:item_2 is null ! so continue alloc memory! ( sysmac [ %s ])", tmp->sys_mac);
					continue;//Make sure the allocation is successful and move on
				}
                rg_wds_json_add_lite_item(tmp, item_2);//coredump
                json_object_array_add(section_1, item_2);
                tmp = tmp->next;
            }
        }
loop1:

        rg_wds_json_add_lite_item(p,item_3);
        json_object_array_add(section_1, item_3);
        json_object_object_add(file_2, "list_pair", section_1);
        json_object_array_add(section_2, file_2);

loop2:
        if (flag_free) {
            json_object_put(section_1);
            json_object_put(file_2);
            json_object_put(item_3);
        }
        p = p->next;
    }

    p = rg_wds_all_info;
    while (p) {
        p->flag = 0;
        p = p->next;
        total++;
    }

    json_object_object_add(file_1, "list_all", section_2);
    memset(wds_total, 0, sizeof(wds_total));
    snprintf(wds_total, sizeof(wds_total), "%u", total);
    json_object_object_add(file_1, "total", json_object_new_string(wds_total));

    int fd;
    const char *str = json_object_to_json_string(file_1);
    rg_wds_misc_clear_file("/tmp/wds_info_lite.json");
    fd = open("/tmp/wds_info_lite.json", O_CREAT | O_RDWR,0644);
    if (fd) {
        write(fd, str, strlen(str));
        close(fd);
    }

    json_object_put(file_1);
end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

char** extractSubstrings(const char* str, int* count) {
	char *saveptr;
	char* copy = strdup(str);
    char* token = strtok_r(copy, CRYPTO_SPLIT_FLAG, &saveptr);
    
    int capacity = 3;
    int size = 0;
    char** substrings = (char**)malloc(capacity * sizeof(char*));
    char *dec_buf = NULL;
    while (token != NULL) {
        if (size >= capacity) {
            capacity *= 2;
            substrings = (char**)realloc(substrings, capacity * sizeof(char*));
        }
        substrings[size] = (char*)malloc(UN_CRYPTO_PART_LEN);
        memset(substrings[size], 0, UN_CRYPTO_PART_LEN);
        char* token_copy = strdup(token);
	pthread_mutex_lock(&rg_wds_crypt_mtx);
        dec_buf = rg_crypto_buf_decrypt(token_copy, strlen(token_copy), 'c');
        if (dec_buf != NULL) {
            memcpy(substrings[size],dec_buf,UN_CRYPTO_PART_LEN);
            rg_crypto_buf_free(dec_buf);
        }
	pthread_mutex_unlock(&rg_wds_crypt_mtx);
        free(token_copy);
        GPIO_DEBUG("substrings:%d,data:%s",size,substrings[size]);
        size++;
        token = strtok_r(NULL, CRYPTO_SPLIT_FLAG, &saveptr);
    }
    free(copy);
    *count = size;
    return substrings;
}

char* rg_wds_decrypto_if(char* str) {
    int count;
    int i = 0;
    if(strstr(str,CRYPTO_SPLIT_FLAG) == NULL) {
        GPIO_DEBUG(" Error:50003 broadcast data lost,drop data");
        return NULL;
    }
    
    char** substrings = extractSubstrings(str, &count);
    GPIO_DEBUG("found %d substrings need decrypto:", count);
    // 计算拼接后的字符串长度
    int totalLength = 0;
    for (i = 0; i < count; i++) {
        totalLength += strlen(substrings[i]);
    }
    
    // 分配内存空间用于存储拼接后的字符串
    char* result = (char*)malloc((totalLength + 2) * sizeof(char));
    result[0] = '\0'; // 确保字符串以'\0'结尾
    
    // 拼接子字符串
    for (i = 0; i < count; i++) {
        strcat(result, substrings[i]);
    }
    
    // 在结果字符串末尾添加"#"
    strcat(result, "#");
    // 将拼接后的字符串复制到str中
    strcpy(str, result);
    free(result);
    //GPIO_DEBUG("--------------->:%s", str);
    // 释放内存空间
    for (i = 0; i < count; i++) {
        free(substrings[i]);
    }
    
    free(substrings);
    return str;
}

void rg_wds_get_info_multi(char *str,int type, bool self) {
    char *p = str;
    char option[100];
    char value[200];
    char sn[30];
    bool b_wait = false;
    struct dev_multi_info *info = NULL;
    struct dev_multi_info *tmp = NULL;
    struct sysinfo sys_time;
    p = p + 1;
    //TODO:判断是否需要解密，数据中存在"###"
    GPIO_DEBUG("-------------> get info type:(%d):\n%s",type,p);
    if(type == TYPE_CRYPTO){
        p = rg_wds_decrypto_if(p);
    }
    
    tmp = malloc(sizeof(struct dev_multi_info));
    if (tmp == NULL) {
        return;
    }
    memset(tmp,0,sizeof(struct dev_multi_info));
	sysinfo(&sys_time);
    
    while (p != NULL) {
        p = rg_wds_get_option_vaule(p,option,sizeof(option),value,sizeof(value));
        
        if (strcmp(option,"sn") == 0) {
            memcpy(tmp->sn,value,strlen(value));
        } else if (strcmp(option,"hostname") == 0) {
            memcpy(tmp->host_name,value,strlen(value));
        } else if (strcmp(option,"ssid") == 0) {
            memcpy(tmp->ssid,value,strlen(value));
        } else if (strcmp(option,"sysmac") == 0) {
            memcpy(tmp->sys_mac,value,strlen(value));
        } else if (strcmp(option,"model") == 0) {
            memcpy(tmp->dev_type,value,strlen(value));
        } else if (strcmp(option,"role") == 0) {
            memcpy(tmp->role,value,strlen(value));
            if(strcmp(tmp->role,"ap")== 0){
                memset(tmp->peer_sn,0,sizeof(tmp->peer_sn));
                memset(tmp->peermac,0,sizeof(tmp->peermac));
            }
        } else if (strcmp(option,"lock") == 0) {
            memcpy(tmp->lock,value,strlen(value));
        } else if (strcmp(option,"athmac") == 0) {
            memcpy(tmp->ath_mac,value,strlen(value));
        } else if (strcmp(option,"softversion") == 0) {
            memcpy(tmp->software_version,value,strlen(value));
        } else if (strcmp(option,"softver_new") == 0) {
            memcpy(tmp->softver_new,value,strlen(value));
        } else if (strcmp(option,"clean_sftn") == 0) {
            memcpy(tmp->clean_sftn,value,strlen(value));
        } else if (strcmp(option,"peersn") == 0) {
            memcpy(tmp->peer_sn,value,strlen(value));
        } else if (strcmp(option,"userIp") == 0) {
            memcpy(tmp->ipaddr,value,strlen(value));
        } else if (strcmp(option,"onlineTime") == 0) {
            memcpy(tmp->time,value,strlen(value));
        } else if (strcmp(option,"band") == 0) {
            memcpy(tmp->band,value,strlen(value));
        } else if (strcmp(option,"rssi") == 0) {
            memcpy(tmp->rssi,value,strlen(value));
        } else if (strcmp(option,"rate") == 0) {
            memcpy(tmp->rate,value,strlen(value));
        } else if (strcmp(option,"channel") == 0) {
            memcpy(tmp->channel,value,strlen(value));
        } else if (strcmp(option,"passwd") == 0) {
            memcpy(tmp->passwd,value,strlen(value));
        } else if (strcmp(option,"channf") == 0) {
            memcpy(tmp->channf,value,strlen(value));
        } else if (strcmp(option,"chutil") == 0) {
            memcpy(tmp->chutil,value,strlen(value));
        } else if (strcmp(option,"distance") == 0) {
            memcpy(tmp->wds_distance,value,strlen(value));
        } else if (strcmp(option,"txpower") == 0) {
            memcpy(tmp->wds_txpower,value,strlen(value));
        } else if (strcmp(option,"phymode") == 0) {
            memcpy(tmp->phymode,value,strlen(value));
        } else if (strcmp(option,"netmask") == 0) {
            memcpy(tmp->netmask,value,strlen(value));
        } else if (strcmp(option,"cwmp") == 0) {
            memcpy(tmp->cwmp,value,strlen(value));
        } else if (strcmp(option,"lan1speed") == 0) {
            memcpy(tmp->lan1speed,value,strlen(value));
        } else if (strcmp(option,"lan1link") == 0) {
            memcpy(tmp->lan1link,value,strlen(value));
        } else if (strcmp(option,"lan1duplex") == 0) {
            memcpy(tmp->lan1duplex,value,strlen(value));
        } else if (strcmp(option,"lan1nosupport") == 0) {
            memcpy(tmp->lan1nosupport,value,strlen(value));
        } else if (strcmp(option,"lan2speed") == 0) {
            memcpy(tmp->lan2speed,value,strlen(value));
        } else if (strcmp(option,"lan2link") == 0) {
            memcpy(tmp->lan2link,value,strlen(value));
        } else if (strcmp(option,"lan2duplex") == 0) {
            memcpy(tmp->lan2duplex,value,strlen(value));
        } else if (strcmp(option,"lan2nosupport") == 0) {
            memcpy(tmp->lan2nosupport,value,strlen(value));
        } else if (strcmp(option,"onlinestatus") == 0) {
            memcpy(tmp->onlinestatus,value,strlen(value));
        } else if (strcmp(option,"rx_rate") == 0) {
            memcpy(tmp->rx_rate,value,strlen(value));
        } else if (strcmp(option,"tx_rate") == 0) {
            memcpy(tmp->tx_rate,value,strlen(value));
        } else if (strcmp(option,"peermac") == 0) {
            memcpy(tmp->peermac,value,strlen(value));
        } else if (strcmp(option,"hardversion") == 0) {
            memcpy(tmp->hardware_version,value,strlen(value));
        } else if (strcmp(option,"rx_speed") == 0) {
            memcpy(tmp->rx_speed,value,strlen(value));
        } else if (strcmp(option,"tx_speed") == 0) {
            memcpy(tmp->tx_speed,value,strlen(value));
        } else if (strcmp(option,"rx_speed_a") == 0) {
            memcpy(tmp->rx_speed_a,value,strlen(value));
        } else if (strcmp(option,"rssi_a") == 0) {
            memcpy(tmp->rssi_a,value,strlen(value));
        } else if (strcmp(option,"chutil_a") == 0) {
            memcpy(tmp->chutil_a,value,strlen(value));
        } else if (strcmp(option,"pingTime") == 0) {
            memcpy(tmp->pingTime,value,strlen(value));
        } else if (strcmp(option,"connectTime") == 0) {
            memcpy(tmp->connectTime,value,strlen(value));
        } else if (strcmp(option,"networkId") == 0) {
            memcpy(tmp->networkid,value,strlen(value));
        } else if (strcmp(option,"networkName") == 0) {
            memcpy(tmp->networkname,value,strlen(value));
        } else if (strcmp(option,"country") == 0) {
            memcpy(tmp->country,value,strlen(value));
        } else if (strcmp(option,"dch") == 0) {
                   tmp->dfs_ch = atoi(value);
        } else if (strcmp(option,"dtm") == 0) {
            memcpy(tmp->dfs_time,value,strlen(value));
        } else if (strcmp(option,"def_pw") == 0) {
            memcpy(tmp->def_pw,value,strlen(value));
        } else if (strcmp(option,"wds_pw") == 0) {
            memcpy(tmp->wds_pw,value,strlen(value));
        } else if (strcmp(option,"wdspw_state") == 0) {
            memcpy(tmp->wdspw_state,value,strlen(value));
        } else if (strcmp(option,"warn_mac") == 0) {
            memcpy(tmp->warn_mac,value,strlen(value));
        } else if (strcmp(option,"manage_ssid") == 0) {
            memcpy(tmp->manage_ssid,value,strlen(value));
        } else if (strcmp(option,"manage_bssid") == 0) {
            memcpy(tmp->manage_bssid,value,strlen(value));
        } else if (strcmp(option,"dc_power") == 0) {
            memcpy(tmp->dc_power,value,strlen(value));
        } else if (strcmp(option,"poe_power") == 0) {
            memcpy(tmp->poe_power,value,strlen(value));
        } else if (strcmp(option,"distance_max") == 0) {
            memcpy(tmp->distance_max,value,strlen(value));
        } else if (strcmp(option,"distance_def") == 0) {
            memcpy(tmp->distance_def,value,strlen(value));
        } else if (strcmp(option,"automatic_range") == 0) {
            memcpy(tmp->automatic_range,value,strlen(value));
        } else if (strcmp(option,"wan_speed") == 0) {
            memcpy(tmp->wan_speed_cap,value,strlen(value));
        } else if (strcmp(option,"scan_dev_cap") == 0) {
            memcpy(tmp->scan_dev_cap,value,strlen(value));
        } else if (strcmp(option,"scan_pw_state") == 0) {
            memcpy(tmp->scan_pw_state,value,strlen(value));
        } else if (strcmp(option,"scan_warn_mac") == 0) {
            memcpy(tmp->host_name,value,strlen(value));
        } else if (strcmp(option,"rssi_align") == 0) {
            memcpy(tmp->rssi_align,value,strlen(value));
        }
    }
    if(self == true){
        b_wait = true;
    }
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    while (self == false && b_wait == true) {
        //非本机的要等待本机优先执行
        pthread_cond_wait(&cond_rg_wds_all_info, &mtx_rg_wds_all_info);
    }
    if (strlen(tmp->sn) != 0) {
        tmp->time_update = sys_time.uptime;
        info = rg_wds_get_info_all_list(tmp);
    }
    free(tmp);
#ifdef EST_SUPPORT_REDIS
    //TODO:这里要写数据库，根据SN匹配链表，指针从里面返回,避免再循环一次
    if(info != NULL) {
        //GPIO_DEBUG("SET TO REDBS SN:%s",info->sn);
        GPIO_DEBUG("get broadcast and set to redis");
        redbs_wds_info_set_pub(info);
        redbs_wds_tipc_set_pub(info);
        #if 0 //取数据库数据测试代码
        struct dev_multi_info *redis_get_test = NULL;
        redis_get_test = malloc(sizeof(struct dev_multi_info));
        if(redis_get_test != NULL) {
            memset(redis_get_test, 0, sizeof(struct dev_multi_info));
            redbs_wds_info_get_pub(info->sn,redis_get_test);
            free(redis_get_test);
        }
        #endif
    }
    //本机执行完唤醒等待的线程
    if(self == true){
        pthread_cond_signal(&cond_rg_wds_all_info);
    }
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
#endif
}

int packet_md5_check(char *data, char *ret)
{
	char *str = data;
	char result1[2048];
	char result2[512];
	char result3[512];
	char* token;
	unsigned char md5str[64];
	unsigned char *md5buf;
	char *saveptr;

	memset(result1, 0, sizeof(result1));
	memset(result2, 0, sizeof(result2));
	memset(result3, 0, sizeof(result3));
	memset(md5str, 0, sizeof(md5str));
	token = strtok_r(str, CRYPTO_SPLIT_FLAG, &saveptr);
	if(token != NULL) {
		strncpy(result1, token, strlen(token));
		strcat(ret, "#");
		strcat(ret, token);
		strcat(ret, CRYPTO_SPLIT_FLAG);
		token = strtok_r(NULL, CRYPTO_SPLIT_FLAG, &saveptr);
		if(token != NULL) {
			strncpy(result2, token, strlen(token));
			token = strtok_r(NULL, CRYPTO_SPLIT_FLAG, &saveptr);
			if(token != NULL) {
				strncpy(result3, token, strlen(token));
				token = strtok_r(NULL, CRYPTO_SPLIT_FLAG, &saveptr);
				if(token != NULL) {
					GPIO_DEBUG("Received the wrong package");
					return 1;
				}
				strncpy(md5str, result3, strlen(result3));
				strcat(ret, result2);
				strcat(ret, CRYPTO_SPLIT_FLAG);
				strcat(result1, CRYPTO_SPLIT_FLAG);
				strcat(result1, result2);
				strcat(result1, CRYPTO_SPLIT_FLAG);
				GPIO_DEBUG("packet md5 str:%s", md5str);
			}
			else{
				strcat(result1, CRYPTO_SPLIT_FLAG);
				strncpy(md5str, result2, strlen(result2));
				GPIO_DEBUG("packet md5 str:%s", md5str);
			}
		}
	}
	md5buf = md5_coding(result1);
	// GPIO_DEBUG("md5buf:%s", md5buf);
	if(strncmp(md5buf, md5str, strlen(md5str)) == 0) {
		GPIO_DEBUG("recv packet md5 check pass");
		return 0;
	}
	GPIO_DEBUG("recv packet md5 check faild");
	return 1;

}


void rg_wds_message_dev_process(char *str, bool b_self) {
    char *p = str;
    char *buf = NULL;
	char *buf1 = NULL;
    
    buf = malloc(2000);
    if (buf == NULL) {
        return;
    }
	
    memset(buf,0,2000);
	
	buf1 = malloc(2000);
    if (buf1 == NULL) {
        free(buf);
        return;
    }
    memset(buf1, 0, 2000);
    
    p = rg_wds_cmp_str(p,buf);

    //合法性检查
    if (rg_wds_check_1(buf) == 0) {
        free(buf);
        return;
    }

    memset(buf,0,sizeof(buf));
    p = rg_wds_cmp_str(p,buf);

    switch (rg_wds_type_process(buf)) {
        case TYPE_INFO:
            if(b_self == false){
                g_count_down = STOP_SEND_CNT;//解析出非本机的50002类型就重新倒计时
            }
            rg_wds_get_info_multi(p, TYPE_INFO, b_self);
            break;
        case TYPE_CRYPTO:
			if(packet_md5_check(p, buf1) != 0) {
				free(buf);
				free(buf1);
				return;
			}
            rg_wds_get_info_multi(buf1, TYPE_CRYPTO ,b_self);
            break;
        default:
            break;
    }
    free(buf);
	free(buf1);
}
