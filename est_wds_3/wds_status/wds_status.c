#include <string.h>
#include <stdio.h>
#include <libubox/list.h>
#include <json-c/json.h>
#include <uci.h>
#include "uf_plugin_intf.h"
#include "wds_status.h"

unsigned char wifi_name[10];
unsigned char role[10];

static uf_plugin_intf_t *g_intf;
#define WDS_STATUS_DEBUG(format, ...) do {\  
    UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\  
} while(0)

static struct json_object *create_wds_status_json()
{
	struct json_object *wds_status_obj;
	wds_status_obj = json_object_new_object();
	if(wds_status_obj == NULL){
		WDS_LINK_QUA_DEBUG("create_wds_status_json wds_status_obj is NULL");
		return NULL;
	}
	
	json_object_object_add(wds_status_obj, "role", json_object_new_string(role));
	json_object_object_add(wds_status_obj, "lock", json_object_new_string("true"));
	json_object_object_add(wds_status_obj, "soft_lock", json_object_new_string("true"));
	json_object_object_add(wds_status_obj, "swi_flag", json_object_new_string("0"));
	return wds_status_obj;
}

int json_get_string_value(struct json_object *js_obj, char *option, char *value, int value_len){
	char * str_js= NULL;
    int str_len = 0; 
	struct json_object *option_obj;
	if (!js_obj || !option || !value){
		WDS_STATUS_DEBUG("Parameter has a null value!!!");
		return FAIL;
	}
	
	option_obj = json_object_object_get(js_obj, option);
	if (!option_obj){
		WDS_STATUS_DEBUG("option=%s", option);
		return FAIL;
	}	
	
	str_js = json_object_to_json_string(option_obj);
	if(!str_js){
		WDS_STATUS_DEBUG("to_json_string error");
		return FAIL;
	}
	str_len = strlen(str_js) - 2;
	if (value_len < str_len){
		WDS_STATUS_DEBUG("%s len > value_len", str_js);
		return FAIL;
	}
	strncpy(value, (str_js + 1), str_len);
	return SUCCESS;
}

char * ReadFile(char * path, int *length)
{
	FILE * pfile;
	char * data = NULL;

	pfile = fopen(path, "rb");
 	if (pfile == NULL) {
        WDS_STATUS_DEBUG("(err)fopen [%s] fail!", path);
        goto rf_end;
	}

	if (fseek(pfile, 0, SEEK_END)) {
        WDS_STATUS_DEBUG("(err)fseek fail!");
        goto rf_end;
    }
	*length = ftell(pfile);
    if (-1L == *length) {
        WDS_STATUS_DEBUG("(err)ftell fail!");
        goto rf_end;
    }
	data = (char *)malloc((*length + 1) * sizeof(char));
    if ( !data ){
        WDS_STATUS_DEBUG("(err)ReadFile[ %s ]malloc fail!", path);
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

void rg_wds_uci_get_param(char *uci_param, char *buff, int len)
{
    struct uci_context *c;
    struct uci_ptr p;
    char *a;

    if (!uci_param || !buff) {
        WDS_STATUS_DEBUG("uci_param or buff is NULL!");
        return;
    }

    a = strdup(uci_param);
    c = uci_alloc_context();
    if (c == NULL || a == NULL) {
        WDS_STATUS_DEBUG("pointer is not valid.");
        goto err;
    }

    if (UCI_OK != uci_lookup_ptr(c, &p, a, true)) {
        WDS_STATUS_DEBUG("uci no found!");
        goto err;
    }

    if (p.o != NULL) {
       strncpy(buff, p.o->v.string, len);
    } else {
       WDS_STATUS_DEBUG("param %s not found", uci_param);
    }

err:
    if (c) {
       uci_free_context(c);
    }
    if (a) {
       free(a);
    }
    return;
}


int wds_status_get_role(char *wifi_name)
{
    int ret;
	char buf[20], get_mode_cmd[50];
	memset(get_mode_cmd, 0, sizeof(get_mode_cmd));
	memset(buf,0,sizeof(buf));
	sprintf(get_mode_cmd, ATH_GET_CMD_MODE,wifi_name);
	rg_wds_uci_get_param(get_mode_cmd, buf, sizeof(buf));
    ret = -1;
	if (strcmp(buf,ATH_MODE_STA) == 0) {
		ret = MODE_CPE;
	} else {
		ret = MODE_AP;
	} 
    return ret;
}

static int wds_status_get_wif_iname(char *wifi_name)
{
    struct json_object *json, *json1, *json2, *json3;
	char json_str_value[20];
    char json_str_value1[20];
    char *str_cap_table = NULL;
	int resout = FAIL;
    int length,i;
  
    str_cap_table = ReadFile(DEV_CAP_DIR, &length);
    if(NULL == str_cap_table){
        WDS_STATUS_DEBUG("(err)Open file[%s] fail!", DEV_CAP_DIR);
        goto end;
    }
    json = NULL;
    json = json_tokener_parse((const char *)str_cap_table);
    if (!json) {
        WDS_STATUS_DEBUG("(err)Fail to get device capacity table json string!");
        goto end;
    }
	json1 = NULL;
    json1 = json_object_object_get(json, "wireless");
    if (!json1) {
        WDS_STATUS_DEBUG("(err)wireless is NULL!");
        goto end;
    }
	memset(json_str_value, 0, sizeof(json_str_value));
	if (json_get_string_value(json1, "radio_num", json_str_value, sizeof(json_str_value))  == FAIL) {
		WDS_STATUS_DEBUG("get radio_num is error");
		goto end;
	}
	int radio_num = atoi(json_str_value);
    WDS_STATUS_DEBUG("radio_num :%d",radio_num);
    json2=NULL;
    json2 = json_object_object_get(json1, "radiolist");
    if (!json2) {
        WDS_STATUS_DEBUG("radiolist is NULL!");
        goto end;
    }

    for (i=0; i<radio_num; i++) {
		json3 = NULL;
        json3 = json_object_array_get_idx(json2, i);
        if (!json3) {
            WDS_STATUS_DEBUG("radiolist[%d] is NULL!", i);
            break;
        }     
		memset(json_str_value1, 0, sizeof(json_str_value1));
        if (json_get_string_value(json3, "support_wds", json_str_value1, sizeof(json_str_value1))  == FAIL) {
			WDS_STATUS_DEBUG("get support_wds is error");
			goto end;
		}

        if (strcmp(json_str_value1, "true") == 0){
            /*get wds_bss from dev cap*/
            memset(wifi_name, 0, 10);
			if (json_get_string_value(json3, "name", wifi_name, 10)  == FAIL) {
				WDS_STATUS_DEBUG("get name is error");
				goto end;
			}
            WDS_STATUS_DEBUG("wifi_name:%s",wifi_name);
		}       
    }
    resout = SUCCESS;
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


static int wds_status_get(char** rbuf)
{
	struct json_object *wds_status_json;
	char *pbuf;
	int ret;

    memset(wifi_name, 0, sizeof(wifi_name));
    wds_status_get_wif_iname(wifi_name);
    WDS_STATUS_DEBUG("wifi_name:%s",wifi_name);
    if(strlen(wifi_name) == 0) {
		WDS_STATUS_DEBUG("get wifi_name faild");
		ret = -1;
		return ret;
	}
    memset(role, 0, sizeof(role));
    ret = wds_status_get_role(wifi_name);
    if(ret == MODE_CPE)
    {
       strcpy(role,ROLE_IS_CPE);
    }else{
       strcpy(role,ROLE_IS_AP);
    }
    WDS_STATUS_DEBUG("role:%s\n", role);
    
	wds_status_json = create_wds_status_json();
	if(wds_status_json == NULL) {
		WDS_STATUS_DEBUG("create_wds_status_json faild");
		ret = -3;
		return ret;
	}

	pbuf = (char *)malloc(PBUF_SIZE);
	if(!pbuf) {
		WDS_STATUS_DEBUG("pbuf malloc memory faild\n");
		ret = -4;
		goto faild_end1;
	}
	*rbuf = pbuf;
	
    strcpy(pbuf, json_object_to_json_string(wds_status_json));
	ret = 0;

faild_end1: 
    if(wds_status_json != NULL) {
        json_object_put(wds_status_json);
    }
        
	return ret;
}

static int handle_fuc(uf_plugin_attr_t *attr, char **rbuf)  
{
    int ret = 0;  
  
    switch(attr->cmd) {  
	    case(UF_CMD_GET):
			ret = wds_status_get(rbuf);
	        break;
	    default:
			WDS_STATUS_DEBUG("<====unsupport cmd====>");
	        break;  
    }
    return ret;  
}  

void module_init_wds_status(uf_plugin_intf_t *intf)  
{  
    strcpy(intf->name, MODULE_NAME);  
    intf->fuc = (uf_handle_fuc)handle_fuc;  
    g_intf = intf;  
    uf_set_plug_debug(g_intf, 0, DEBUG_LOG_SIZE, DEBUG_LOG_LINE_SIZE);
    WDS_STATUS_DEBUG("<======init wds_status=========>");  
    return ;  
}  

