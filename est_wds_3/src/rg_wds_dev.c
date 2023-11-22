#include "rg_wds.h"

//Device capacity table struct
struct  dev_capacity_table rg_dev_capacity_table;

#define DEV_GET_HOSTNAME_CMD         "system.@system[0].hostname"
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

int wds_get_dev_sysmac(char *buf,char len)
{
	//rg_wds_misc_read_file(DEV_FILE_SYSMAC,buf,len);
	char dev_eth_name[6];
    int dev_name_len;
    dev_name_len = strlen(rg_dev_capacity_table.dev_name);
    memset(dev_eth_name, 0, sizeof(dev_eth_name));
    if (0 == dev_name_len) {
        GPIO_ERROR("(err)Dev capacity table struct dev_name is null!!!");
        return FAIL;
    } else if (dev_name_len > sizeof(dev_eth_name)) {
        GPIO_ERROR("(err)dev_name_len more than dev_eth_nam size");
        return FAIL;
    } else {
        strcpy(dev_eth_name, rg_dev_capacity_table.dev_name);
    }
    if (FAIL == rg_wds_misc_get_mac(dev_eth_name,buf)) {
        GPIO_ERROR("(err)Get sysmac fail!");
        return FAIL;
    }
	return SUCESS;
}

char wds_get_dev_sn(char *buf,char len)
{
	rg_wds_misc_read_file(DEV_FILE_SN,buf,len);
}

char wds_get_dev_ip(u_int32_t *ip)
{
	*ip = rg_wds_misc_get_iface_ip(DEV_IP_ADDRESS_INTERFACE);
}

void rg_wds_dev_update(struct dev_info *dev_info_t) {
	wds_get_dev_ip(&(dev_info_t->ip));
	memset(dev_info_t->host_name, 0, sizeof(dev_info_t->host_name));
	rg_wds_uci_get_param(DEV_GET_HOSTNAME_CMD, dev_info_t->host_name, sizeof(dev_info_t->host_name));
	GPIO_DEBUG("dev_info_t->host_name:%s", dev_info_t->host_name);
}

char rg_wds_dev_init(struct dev_info *dev_info_t)
{
	memset(dev_info_t,0,sizeof(struct dev_info));
	wds_get_dev_type(dev_info_t->dev_type,sizeof(dev_info_t->dev_type) - 1);
	wds_get_dev_hardware_version(dev_info_t->hardware_version,sizeof(dev_info_t->hardware_version));
    wds_get_dev_software_version(dev_info_t->software_version,sizeof(dev_info_t->software_version));
	wds_get_dev_sysmac(dev_info_t->sys_mac,sizeof(dev_info_t->sys_mac) - 1);
	//GPIO_DEBUG("-------------");
	//GPIO_DEBUG("init sysmac :%02x:%02x:%02x:%02x:%02x:%02x",dev_info_t->sys_mac[0],dev_info_t->sys_mac[1],dev_info_t->sys_mac[2],dev_info_t->sys_mac[3],dev_info_t->sys_mac[4],dev_info_t->sys_mac[5]);
	wds_get_dev_sn(dev_info_t->sn,sizeof(dev_info_t->sn) - 1);
	GPIO_DEBUG("dev init ---dev_info_t->sn:%s", dev_info_t->sn);
	wds_get_dev_ip(&(dev_info_t->ip));
	
	memset(dev_info_t->host_name, 0, sizeof(dev_info_t->host_name));
	rg_wds_uci_get_param(DEV_GET_HOSTNAME_CMD, dev_info_t->host_name, sizeof(dev_info_t->host_name));
	GPIO_DEBUG("dev_info_t->host_name:%s", dev_info_t->host_name);
}

char rg_wds_dev_match()
{
	rg_gpio_info_t.gpio_lock_num = LOCK_GPIO;
	rg_gpio_info_t.gpio_mode_num = MODE_GPIO;

	rg_gpio_info_t.gpio_lock_value = LOCK;
	rg_gpio_info_t.gpio_mode_value = rg_ath_info_t.role;

	rg_gpio_info_t.gpio_lock_value_last = rg_gpio_info_t.gpio_lock_value;
	rg_gpio_info_t.gpio_mode_value_last= rg_gpio_info_t.gpio_mode_value;
	GPIO_DEBUG("gpio_lock_value %d gpio_mode_value %d",rg_gpio_info_t.gpio_lock_value,rg_gpio_info_t.gpio_mode_value);
}

void rg_wds_dev_reboot () {
	GPIO_DEBUG("reboot dev");
	system("reboot");
}


char * ReadFile(char * path, int *length)
{
	FILE * pfile;
	char * data = NULL;
    
	pfile = fopen(path, "rb");
 	if (pfile == NULL) {
        GPIO_ERROR("(err)fopen [%s] fail!", path);
        goto rf_end;
	}
	if (fseek(pfile, 0, SEEK_END)) {
        GPIO_ERROR("(err)fseek fail!");
        goto rf_end;
    }
	*length = ftell(pfile);
    if (-1L == *length) {
        GPIO_ERROR("(err)ftell fail!");
        goto rf_end;
    }
	data = (char *)malloc((*length + 1) * sizeof(char));
    if ( !data ){
        GPIO_ERROR("(err)ReadFile[ %s ]malloc fail!", path);
        goto rf_end;
    }
    memset(data, 0, *length + 1);
	rewind(pfile);
	*length = fread(data, 1, *length, pfile);
	data[*length] = '\0';
rf_end:
    if (pfile) {
        fclose(pfile);
    }
	return data;
}

void dev_cap_show(){
	
	GPIO_DEBUG("-----------%-*s-----------", 18, "dev_cap show start");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s", 5, "|", 16, "dev_name", 10, rg_dev_capacity_table.dev_name, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "switch_num", rg_dev_capacity_table.switch_num, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s", 5, "|", 16, "switch_name", 10, rg_dev_capacity_table.switch_name, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s", 5, "|", 16, "wifi_name",10, rg_dev_capacity_table.wifi_name, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s", 5, "|", 16, "support_ra", 10, rg_dev_capacity_table.support_ra, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "radio", rg_dev_capacity_table.radio, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s",5, "|", 16, "wds_pw", 10, rg_dev_capacity_table.wds_pw, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s", 5, "|", 16, "wds_ifname", 10, rg_dev_capacity_table.wds_ifname, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s", 5, "|", 16, "manage_ifname", 10, rg_dev_capacity_table.mag_ifname, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "dc_power", rg_dev_capacity_table.dc_power, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "poe_power", rg_dev_capacity_table.poe_power, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "distance_max", rg_dev_capacity_table.distance_max, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-10d%*s", 5, "|", 16, "distance_def", rg_dev_capacity_table.distance_def, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "automa_range", rg_dev_capacity_table.automatic_range, 5, "|");
	GPIO_DEBUG("%-*s %-*s:  %-*s %*s",5, "|", 16, "scan_dev_cap", 10, rg_dev_capacity_table.scan_dev_cap, 5, "|");
    GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "poe_power", rg_dev_capacity_table.rssi_align, 5, "|");
	int i;
	for(i=0; i<SWITCH_PORT_LENGTH; i++ ){
		GPIO_DEBUG("%-*s %-*s:  %-10d %*s",5, "|", 16, "switch_port", rg_dev_capacity_table.switch_port[i], 5, "|");
	}
	GPIO_DEBUG("%-*s %-*s:  %-10d %*s", 5, "|", 16, "wan_speed", rg_dev_capacity_table.wan_speed, 5, "|");	

	GPIO_DEBUG("-----------%-*s-----------", 18, "dev_cap show end");
	
}

int json_get_string_value(struct json_object *js_obj, char *option, char *value, int value_len){
	char * str_js= NULL;
    int str_len = 0; 
	struct json_object *option_obj;
	if (!js_obj || !option || !value){
		GPIO_ERROR("Parameter has a null value!!!");
		return FAIL;
	}
	
	option_obj = json_object_object_get(js_obj, option);
	if (!option_obj){
		GPIO_ERROR("option=%s", option);
		return FAIL;
	}	
	
	str_js = json_object_to_json_string(option_obj);
	if(!str_js){
		GPIO_ERROR("to_json_string error");
		return FAIL;
	}
	str_len = strlen(str_js) - 2;
	if (value_len < str_len){
		GPIO_ERROR("%s len > value_len", str_js);
		return FAIL;
	}
	strncpy(value, (str_js + 1), str_len);
	return SUCESS;
}



int dev_capacity_init(struct  dev_capacity_table* rg_dev_capacity_t)
{
    struct json_object *json, *arr_item, *json1, *json2, *json3;
	char json_str_value[20];
    char json_str_value1[20];
    char *str_cap_table;
	int resout = FAIL;
    int length;
   
    str_cap_table = ReadFile(DEV_CAP_DIR, &length);
    if(NULL == str_cap_table){
        GPIO_ERROR("(err)Open file[%s] fail!", DEV_CAP_DIR);
        goto end;
    }
    json = NULL;
    json = json_tokener_parse((const char *)str_cap_table);
    if (!json) {
        GPIO_ERROR("(err)Fail to get device capacity table json string!");
        goto end;
    }
    json1 = json_object_object_get(json, "eth");
    if (!json1) {
        GPIO_ERROR("eth is NULL!");
        goto end;
    }
    json2 = json_object_object_get(json1, "eth_dev");
    if (!json2) {
        GPIO_ERROR("eth_dev is NULL!");
        goto end;
    }
    arr_item = json_object_array_get_idx(json2, 0);
    if (!arr_item) {
        GPIO_ERROR("eth_dev[0] is NULL!");
        goto end;
    }

	memset(rg_dev_capacity_t->dev_name, 0, sizeof(rg_dev_capacity_t->dev_name));
	if (json_get_string_value(arr_item, "dev_name", rg_dev_capacity_t->dev_name, sizeof(rg_dev_capacity_t->dev_name))  == FAIL) {
		GPIO_WARNING("get dev_name  is error");
		goto end;		  //An array member does not have a switch port
	}

	/*Start parsing the switch  */
	json1 = NULL;
    json1 = json_object_object_get(json, "eth_port");
    if (!json1) {
        GPIO_ERROR("(err)eth_port is NULL!");
        goto end;
    }
	json2 = NULL;
	json2 = json_object_object_get(json1, "switch");
	if (!json2) {
        GPIO_DEBUG("switch is NULL!");
        goto end;
    }
	json3 = NULL;
	json3 = json_object_array_get_idx(json2, 0);
	if (!json3) {
        GPIO_ERROR("sw_arr is NULL!");
        goto end;
    }
	memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json3, "sw_name", rg_dev_capacity_t->switch_name, sizeof(rg_dev_capacity_t->switch_name))  == FAIL) {
		GPIO_WARNING("get sw_name  is error");
		goto end;         //An array member does not have a switch port
	}
	/* End Parsing switch */

	/*Start parsing the interface*/
	json2 = NULL;
    json2 = json_object_object_get(json1, "interface");
    if (!json2) {
        GPIO_ERROR("interface is NULL!");
        goto end;
    }
	
	arr_item = NULL;
	arr_item = json_object_array_get_idx(json2, 0);
	if (!arr_item) {
        GPIO_DEBUG("0 arr_item is NULL!");
		goto end;
    }
	struct json_object *speed = NULL;
    speed = json_object_object_get(arr_item, "speed");
    if (!speed) {
       GPIO_DEBUG("speed is NULL!");
       goto end;
    }
	
	rg_dev_capacity_t->wan_speed = atoi(json_object_get_string(speed));
	GPIO_DEBUG("rg_dev_capacity_t->wan_speed=%d", rg_dev_capacity_t->wan_speed);

	arr_item = NULL;
	
	memset(rg_dev_capacity_t->switch_port, 0, sizeof(rg_dev_capacity_t->switch_port));
	int i = 0;
    for (i=0; i<json_object_array_length(json2); i++) {

		rg_dev_capacity_t->switch_port[i] = -1; //初始化为-1

		arr_item = NULL;
        arr_item = json_object_array_get_idx(json2, i);
        if (!arr_item) {
            GPIO_ERROR("arr_item is NULL!");
            break;
        }

		memset(json_str_value, 0, sizeof(json_str_value));
		if (json_get_string_value(arr_item, "index", json_str_value, sizeof(json_str_value))  == FAIL) {
			GPIO_ERROR("get interface[ %d ] index is error", i);
			goto end;
		}
		if (atoi(json_str_value) > 0){
			rg_dev_capacity_t->switch_num ++;
		}

		memset(json_str_value, 0, sizeof(json_str_value));
		if (json_get_string_value(arr_item, "switch_port", json_str_value, sizeof(json_str_value))  == FAIL) {
			GPIO_WARNING("get interface[ %d ] switch_port is error", i);
			continue;          //An array member does not have a switch port
		}
		rg_dev_capacity_t->switch_port[i] = atoi(json_str_value); 
    }
	/* End Parsing interface */
	
    //查设备能力表支持的芯片以及是2.4G还是5G
    json1 = NULL;
    json1 = json_object_object_get(json, "wireless");
    if (!json1) {
        GPIO_ERROR("(err)wireless is NULL!");
        goto end;
    }

	memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json1, "radio_num", json_str_value, sizeof(json_str_value))  == FAIL) {
		GPIO_ERROR("get radio_num is error");
		goto end;
	}
	int radio_num = atoi(json_str_value);
	bool if_2g_wds = false;
    bool if_2g_mng = false;
    bool if_5g_wds = false;
    bool if_5g_mng = false;
    json2=NULL;
    json2 = json_object_object_get(json1, "radiolist");
    if (!json2) {
        GPIO_ERROR("radiolist is NULL!");
        goto end;
    }

    for (i=0; i<radio_num; i++) {
		json3 = NULL;
        json3 = json_object_array_get_idx(json2, i);
        if (!json3) {
            GPIO_ERROR("radiolist[%d] is NULL!", i);
            break;
        }
		
		memset(json_str_value, 0, sizeof(json_str_value));
		if (json_get_string_value(json3, "disabled", json_str_value, sizeof(json_str_value))  == FAIL) {
			GPIO_ERROR("get disabled is error");
			goto end;
		}
		
        if(strcmp(json_str_value, "0") == 0){
            
			memset(json_str_value, 0, sizeof(json_str_value));
            if (json_get_string_value(json3, "band_support", json_str_value, sizeof(json_str_value))  == FAIL) {
			GPIO_ERROR("get band_support is error");
			goto end;
		    }
            
			memset(json_str_value1, 0, sizeof(json_str_value1));
            if (json_get_string_value(json3, "support_wds", json_str_value1, sizeof(json_str_value1))  == FAIL) {
				GPIO_ERROR("get support_wds is error");
				goto end;
			}

            if (strcmp(json_str_value1, "true") == 0){
                /*get wds_bss from dev cap*/
            	memset(rg_dev_capacity_t->wds_ifname, 0, sizeof(rg_dev_capacity_t->wds_ifname));
            	if (json_get_string_value(json3, "wds_bss", rg_dev_capacity_t->wds_ifname, sizeof(rg_dev_capacity_t->wds_ifname))  == FAIL) {
            		GPIO_ERROR("get wds_bss is error");
            		goto end;
            	}
                if (strcmp(json_str_value, "2.4G") == 0){
    				if_2g_wds = true;
    			}else if(strcmp(json_str_value, "5G") == 0){
    				if_5g_wds = true;
    			}else {
    				GPIO_ERROR("wireless.radiolist.band_support not 2.4G and 5G");
    			}
                
                memset(rg_dev_capacity_t->wifi_name, 0, sizeof(rg_dev_capacity_t->wifi_name));
    			if (json_get_string_value(json3, "name", rg_dev_capacity_t->wifi_name, sizeof(rg_dev_capacity_t->wifi_name))  == FAIL) {
    				GPIO_ERROR("get name is error");
    				goto end;
    			}

                memset(rg_dev_capacity_t->wds_cpe_ifname, 0, sizeof(rg_dev_capacity_t->wds_cpe_ifname));
    			if (json_get_string_value(json3, "cpe_bridge_interface", rg_dev_capacity_t->wds_cpe_ifname, sizeof(rg_dev_capacity_t->wds_cpe_ifname))  == FAIL) {
    				GPIO_ERROR("get cpe bridge interface is error");
    				goto end;
    			}
			}
            
			memset(json_str_value1, 0, sizeof(json_str_value1));
            if (json_get_string_value(json3, "support_manage", json_str_value1, sizeof(json_str_value1))  == FAIL) {
				GPIO_ERROR("get support_manage is error");
				goto end;
			}

            if (strcmp(json_str_value1, "true") == 0){
                /*get  manage_bss from dev cap*/
                memset(rg_dev_capacity_t->mag_ifname, 0, sizeof(rg_dev_capacity_t->mag_ifname));
                if (json_get_string_value(json3, "manage_bss", rg_dev_capacity_t->mag_ifname, sizeof(rg_dev_capacity_t->mag_ifname))  == FAIL) {
                    GPIO_ERROR("get manage_bss is error");
                    goto end;
                } 
                if (strcmp(json_str_value, "2.4G") == 0){
    				if_2g_mng = true;
    			}else if(strcmp(json_str_value, "5G") == 0){
    				if_5g_mng = true;
    			}else {
    				GPIO_ERROR("wireless.radiolist.band_support not 2.4G and 5G");
    			}
			}            

			//初始化支持的"ext_ifname": "ra"
			memset(json_str_value, 0, sizeof(json_str_value));
			if (json_get_string_value(json3, "ext_ifname", json_str_value, sizeof(json_str_value))  == FAIL) {
				GPIO_ERROR("get ext_ifname is error");
				goto end;
			}
			sprintf(rg_dev_capacity_t->support_ra, "%s1",json_str_value);
        }
    }

    if (if_2g_mng == true && if_2g_wds  == true) {
        rg_dev_capacity_t->radio = MNG_2G_WDS_2G;
    } else if (if_5g_mng == true && if_5g_wds  == true) {
        rg_dev_capacity_t->radio = MNG_5G_WDS_5G;
    } else if (if_2g_mng == true && if_5g_wds  == true) {
        rg_dev_capacity_t->radio = MNG_2G_WDS_5G;
    } else {
        GPIO_ERROR("other combination not support now");
    }
    
	memset(rg_dev_capacity_t->wds_pw, 0, sizeof(rg_dev_capacity_t->wds_pw));
	if (json_get_string_value(json1, "wds_pw", rg_dev_capacity_t->wds_pw, sizeof(rg_dev_capacity_t->wds_pw))  == FAIL) {
		GPIO_ERROR("get wds_pw is error");
		goto end;
	}	
	memset(rg_dev_capacity_t->scan_dev_cap, 0, sizeof(rg_dev_capacity_t->scan_dev_cap));
	if (json_get_string_value(json1, "scan_dev_cap", rg_dev_capacity_t->scan_dev_cap, sizeof(rg_dev_capacity_t->scan_dev_cap))  == FAIL) {
		GPIO_ERROR("get scan_dev_cap is error");
		goto end;
	}
	
	/*Gets the distance parameters supported by the device*/
	json2=NULL;
	json2 = json_object_object_get(json1, "distance");
	memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json2, "distance_max", json_str_value, sizeof(json_str_value))  == FAIL) {
		GPIO_ERROR("get distance_max is error");
		goto end;
	}
	rg_dev_capacity_t->distance_max = atoi(json_str_value);

	memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json2, "distance_def", json_str_value, sizeof(json_str_value))  == FAIL) {
		GPIO_ERROR("get distance_def is error");
		goto end;
	}
	rg_dev_capacity_t->distance_def = atoi(json_str_value);

	memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json2, "automatic_range", json_str_value, sizeof(json_str_value))  == FAIL) {
		GPIO_ERROR("get automatic_range is error");
		goto end;
	}
	rg_dev_capacity_t->automatic_range = atoi(json_str_value);
	
    /* get "dcUserCtrl" Determine whether the device supports DC power */
    json1 = NULL;
    json1 = json_object_object_get(json, "eweb");
    if (!json1) {
        GPIO_ERROR("(err)eweb is NULL!");
        goto end;
    }

	memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json1, "dcUserCtrl", json_str_value, sizeof(json_str_value))  == FAIL) {
		GPIO_ERROR("get dcUserCtrl is error");
		goto end;
	}
    rg_dev_capacity_t->dc_power = atoi(json_str_value);

    /* get "poeUserControl" Determine whether the device supports POE power */
    memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json1, "poeUserControl", json_str_value, sizeof(json_str_value))  == FAIL) {
		GPIO_ERROR("get poeUserControl is error");
		goto end;
	}
    rg_dev_capacity_t->poe_power = atoi(json_str_value);
    
    memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json1, "rssi_align", json_str_value, sizeof(json_str_value))  == FAIL) {
		GPIO_ERROR("get rssi_align is error");
		goto end;
	}
    rg_dev_capacity_t->rssi_align = atoi(json_str_value);

	dev_cap_show();
    resout = SUCESS;

end:
    if (json) {
        json_object_put(json);
    }
    if (str_cap_table) {
        free(str_cap_table);
        str_cap_table = NULL;
    }
    return resout;
}

