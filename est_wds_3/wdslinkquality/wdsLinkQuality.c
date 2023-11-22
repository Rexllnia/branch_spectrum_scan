#include <string.h>
#include <stdio.h>
#include <libubox/list.h>
#include <json-c/json.h>
#include <hiredis/redbs.h>
#include <hiredis/hiredis.h>
#include <hiredis/redbs_common.h>
#include <hiredis/est/wds/wdsinfo.pb-c.h>
#include <hiredis/est/wds/wdsrssi.pb-c.h>
#include <uci.h>
#include "uf_plugin_intf.h"
#include "wdslinkquality.h"


static uf_plugin_intf_t *g_intf;
#define WDS_LINK_QUA_DEBUG(format, ...) do {\  
    UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\  
} while(0)

static redbs_t *wds_link_qua_dbs = NULL;
static LIST_HEAD(wds_link_qua_list);

unsigned char dev_sn[30];
unsigned char role[10];

static void redbs_wds_db2wds_info(WWdsinfo__InfoTable *info_table, struct wds_info *wds_info)
{
    strcpy(wds_info->sn, info_table->keys->sn);
    if(info_table->peer_sn != NULL){strcpy(wds_info->peer_sn, info_table->peer_sn);}
    if(info_table->sys_mac != NULL){strcpy(wds_info->sys_mac, info_table->sys_mac);}
    if(info_table->ath_mac != NULL){strcpy(wds_info->ath_mac, info_table->ath_mac);}
    if(info_table->peermac != NULL){strcpy(wds_info->peermac, info_table->peermac);}
    if(info_table->channf != NULL){strcpy(wds_info->channf, info_table->channf);}
    if(info_table->chutil != NULL){strcpy(wds_info->chutil, info_table->chutil);}
    if(info_table->role != NULL){strcpy(wds_info->role, info_table->role);}   
    if(info_table->pingtime != NULL){strcpy(wds_info->pingTime, info_table->pingtime);}
    return;
}

static int redbs_wds_info_get_pub(unsigned char *sn, struct wds_info *redis_info)
{
    WWdsinfo__InfoTable info_table ,*p_info_table;
    info_table = (WWdsinfo__InfoTable)W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key;
    info_key = (WWdsinfo__InfoTableKey)W_WDSINFO__INFO_TABLE_KEY__INIT; 
    info_key.sn = sn;
    info_table.keys = &info_key;
    p_info_table = (WWdsinfo__InfoTable *)redbs_get(wds_link_qua_dbs, REDBS_HOST_DB, (const redbs_obj *)&info_table);
        if(!p_info_table) {
            WDS_LINK_QUA_DEBUG("get redis sn fail :%s", sn);
            return FAIL;
        } else {
			redbs_wds_db2wds_info(p_info_table, redis_info);
            redbs_hash_res_free((redbs_obj*)p_info_table);
        }
    return 0;  
}

static void redbs_wds_rssi_db2rssi_info(WWdsrssi__RssiTable *info_table, struct rssi_info *rssi_table)
{
	if(info_table->uplink_rssi_h != NULL){rssi_table->uplink_rssi_h = info_table->uplink_rssi_h;}
	if(info_table->uplink_rssi_v != NULL){rssi_table->uplink_rssi_v = info_table->uplink_rssi_v;}
	if(info_table->downlink_rssi_h != NULL){rssi_table->downlink_rssi_h = info_table->downlink_rssi_h;}
	if(info_table->downlink_rssi_v != NULL){rssi_table->downlink_rssi_v = info_table->downlink_rssi_v;}
}

static int redbs_wds_rssi_info_get_pub(char *peermac_key, struct rssi_info *rssi_info)
{
	WWdsrssi__RssiTable rssi_table, *p_rssi_table; 
    rssi_table = (WWdsrssi__RssiTable)W_WDSRSSI__RSSI_TABLE__INIT;
    WWdsrssi__RssiTableKey rssi_key;
    rssi_key = (WWdsrssi__RssiTableKey)W_WDSRSSI__RSSI_TABLE_KEY__INIT;
	rssi_key.peer_mac.len = 6;
	rssi_key.peer_mac.data = peermac_key;
	rssi_table.keys = &rssi_key;
	p_rssi_table = (WWdsrssi__RssiTable *)redbs_get(wds_link_qua_dbs, REDBS_HOST_DB, (const redbs_obj *)&rssi_table);
	if(!p_rssi_table) {
        WDS_LINK_QUA_DEBUG("get peermac rssi redis fail");
        return FAIL;
	}
	else {
		redbs_wds_rssi_db2rssi_info(p_rssi_table, rssi_info);
		redbs_hash_res_free((redbs_obj*)p_rssi_table);
	}
	return 0;
}

/*
 * 从sysinfo获取本机的sn
 */
static int get_sn_by_uci(unsigned char *buf,char len)
{
	struct uci_context *ctx_sysinfo;
	struct uci_package *pkg_sysinfo;
	struct uci_element *ele_sysinfo;
	struct uci_section *sec_sysinfo;
	const char *pvalue;
	
	ctx_sysinfo = uci_alloc_context();
	if (UCI_OK != uf_uci_load(ctx_sysinfo, UCI_SYSINFO_FILE, &pkg_sysinfo)) {
    	uci_free_context(ctx_sysinfo);
    	WDS_LINK_QUA_DEBUG("get SN by uci FAIL");
    	return FAIL;
    }
	uci_foreach_element(&pkg_sysinfo->sections, ele_sysinfo) {
		sec_sysinfo = uci_to_section(ele_sysinfo);
		if (NULL != (pvalue = uci_lookup_option_string(ctx_sysinfo, sec_sysinfo, "serial_num"))) {
        	memset(buf,0,len);
        	strcpy(buf,pvalue);
        }	
	}
	
	uf_uci_unload(ctx_sysinfo, pkg_sysinfo);
	uci_free_context(ctx_sysinfo);

	return SUCCESS;
}

static int wds_link_qua_scan_cb(const redbs_t *dbs, redbs_pubsub_msg_t *msg, void *arg) 
{
	WWdsinfo__InfoTable *info_table;
	WWdsinfo__InfoTableKey *info_key;
	wds_link_qua_t *wds_link_qua;
	unsigned char peer_mac[6];

	if(msg->error != 0) {
		WDS_LINK_QUA_DEBUG("error occur %d\n", msg->error);
		return FAIL;
	}

    if (msg->cmd == REDBS_CMD_SCAN) {
        if (msg->flag == 0) {   							/* 数据库scan开�?*/
            WDS_LINK_QUA_DEBUG("[wds_link_quality] start\n");
        } else if (msg->flag == REDBS_SCAN_OVER) {  		/* 数据库scan结束 */
            WDS_LINK_QUA_DEBUG("[wds_link_quality] end\n");
        }
    } else if (msg->cmd == REDBS_CMD_HSET || msg->cmd == REDBS_CMD_SET) {
    	info_table = (WWdsinfo__InfoTable *)(msg->value);
		wds_link_qua = (wds_link_qua_t *)malloc(sizeof(wds_link_qua_t));
		if(!wds_link_qua) {
			WDS_LINK_QUA_DEBUG("malloc memory faild\n");
			return FAIL;
		}
		memset(wds_link_qua, 0, sizeof(wds_link_qua_t));
		redbs_wds_db2wds_info(info_table, &wds_link_qua->wds_info);
		if(strcmp(dev_sn, wds_link_qua->wds_info.peer_sn) ==0 || strcmp(dev_sn, wds_link_qua->wds_info.sn) == 0) {
			if(strcmp("cpe",wds_link_qua->wds_info.role) == 0) {
				sscanf(wds_link_qua->wds_info.ath_mac, "%02x:%02x:%02x:%02x:%02x:%02x", &peer_mac[0], &peer_mac[1], &peer_mac[2], &peer_mac[3], &peer_mac[4], &peer_mac[5]);
				// WDS_LINK_QUA_DEBUG("peer_mac:%02x:%02x:%02x:%02x:%02x:%02x", peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3], peer_mac[4], peer_mac[5]);
				redbs_wds_rssi_info_get_pub(peer_mac, &wds_link_qua->rssi_info);
			}
			INIT_LIST_HEAD(&wds_link_qua->wlq_head);
     		list_add_tail(&wds_link_qua->wlq_head, &wds_link_qua_list);
		}
		else {
			free(wds_link_qua);
		}
	}

	return SUCCESS;
}

static int ap_get_wds_list_info(void) 
{
	WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
	WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
	int ret;
	
	info_table.keys = &info_key;
	ret = redbs_scan(wds_link_qua_dbs, REDBS_HOST_DB, (const redbs_obj *)&info_table, 0, wds_link_qua_scan_cb, NULL);
	return ret;
}

static int cpe_get_wds_list_info(unsigned char *devsn) 
{
	wds_link_qua_t *wds_link_qua;
	wds_link_qua_t *peer_wds_link_qua;
	unsigned char peersn[30];
	unsigned char peer_mac[6];
	
	wds_link_qua = (wds_link_qua_t *)malloc(sizeof(wds_link_qua_t));
	if(!wds_link_qua) {
		WDS_LINK_QUA_DEBUG("malloc memory faild\n");
		return FAIL;
	}
	memset(wds_link_qua, 0, sizeof(wds_link_qua_t));
	redbs_wds_info_get_pub(devsn, &wds_link_qua->wds_info);

	INIT_LIST_HEAD(&wds_link_qua->wlq_head);
	list_add_tail(&wds_link_qua->wlq_head, &wds_link_qua_list);
	
	if(strlen(wds_link_qua->wds_info.peer_sn) != 0) {
		strcpy(peersn, wds_link_qua->wds_info.peer_sn);
		peer_wds_link_qua = (wds_link_qua_t *)malloc(sizeof(wds_link_qua_t));
		if(!peer_wds_link_qua) {
			WDS_LINK_QUA_DEBUG("malloc memory faild\n");
			return FAIL;
		}
		memset(peer_wds_link_qua, 0, sizeof(wds_link_qua_t));
		redbs_wds_info_get_pub(peersn, &peer_wds_link_qua->wds_info);
		if(strlen(peer_wds_link_qua->wds_info.ath_mac) != 0) {
			sscanf(peer_wds_link_qua->wds_info.ath_mac, "%02x:%02x:%02x:%02x:%02x:%02x", &peer_mac[0], &peer_mac[1], &peer_mac[2], &peer_mac[3], &peer_mac[4], &peer_mac[5]);
			// WDS_LINK_QUA_DEBUG("peer_mac:%02x:%02x:%02x:%02x:%02x:%02x", peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3], peer_mac[4], peer_mac[5]);
			redbs_wds_rssi_info_get_pub(peer_mac, &peer_wds_link_qua->rssi_info);
		}

		INIT_LIST_HEAD(&peer_wds_link_qua->wlq_head);
		list_add_tail(&peer_wds_link_qua->wlq_head, &wds_link_qua_list);
	}
	
	return SUCCESS;
}

static struct json_object *create_wdslinkquality_json()
{
	struct json_object *wds_link_qua_obj;
	struct json_object *dev_list_node;
	struct json_object *dev_list;

	wds_link_qua_t *obj;
	char tmp[32];

	wds_link_qua_obj = json_object_new_object();
	if(wds_link_qua_obj == NULL){
		WDS_LINK_QUA_DEBUG("create_wdslinkquality_json wds_link_qua_obj is NULL");
		return NULL;
	}
	
	dev_list = json_object_new_array();
	if(dev_list == NULL){
		WDS_LINK_QUA_DEBUG("create_wdslinkquality_json dev_list is NULL");
		json_object_put(wds_link_qua_obj);
		return NULL;
	}	

	list_for_each_entry(obj, &wds_link_qua_list, wlq_head) {
		if(!strncmp(dev_sn, obj->wds_info.sn, strlen(dev_sn))) {
			json_object_object_add(wds_link_qua_obj, "sn", json_object_new_string(obj->wds_info.sn));
			json_object_object_add(wds_link_qua_obj, "role", json_object_new_string(obj->wds_info.role));
			json_object_object_add(wds_link_qua_obj, "devmac", json_object_new_string(obj->wds_info.sys_mac));
			json_object_object_add(wds_link_qua_obj, "athmac", json_object_new_string(obj->wds_info.ath_mac));
			json_object_object_add(wds_link_qua_obj, "pingTime", json_object_new_string(obj->wds_info.pingTime));
			json_object_object_add(wds_link_qua_obj, "chutil", json_object_new_string(obj->wds_info.chutil));
			json_object_object_add(wds_link_qua_obj, "channf", json_object_new_string(obj->wds_info.channf));
		}
		else {
			dev_list_node = json_object_new_object();
			if(dev_list_node == NULL){
				WDS_LINK_QUA_DEBUG("create_wdslinkquality_json dev_list_node is NULL");
				json_object_put(dev_list);
				json_object_put(wds_link_qua_obj);
				return NULL;
			}	
			json_object_object_add(dev_list_node, "sn", json_object_new_string(obj->wds_info.sn));
			json_object_object_add(dev_list_node, "role", json_object_new_string(obj->wds_info.role));
			json_object_object_add(dev_list_node, "devmac", json_object_new_string(obj->wds_info.sys_mac));
			json_object_object_add(dev_list_node, "athmac", json_object_new_string(obj->wds_info.ath_mac));
			json_object_object_add(dev_list_node, "pingTime", json_object_new_string(obj->wds_info.pingTime));
			json_object_object_add(dev_list_node, "chutil", json_object_new_string(obj->wds_info.chutil));
			json_object_object_add(dev_list_node, "channf", json_object_new_string(obj->wds_info.channf));

			memset(tmp, 0, sizeof(tmp));
    		sprintf(tmp, "%d", obj->rssi_info.uplink_rssi_h);
			json_object_object_add(dev_list_node, "uplink_rssi_h", json_object_new_string(tmp));
			memset(tmp, 0, sizeof(tmp));
    		sprintf(tmp, "%d", obj->rssi_info.uplink_rssi_v);
			json_object_object_add(dev_list_node, "uplink_rssi_v", json_object_new_string(tmp));
			memset(tmp, 0, sizeof(tmp));
    		sprintf(tmp, "%d", obj->rssi_info.downlink_rssi_h);
			json_object_object_add(dev_list_node, "downlink_rssi_h", json_object_new_string(tmp));
			memset(tmp, 0, sizeof(tmp));
    		sprintf(tmp, "%d", obj->rssi_info.downlink_rssi_v);
			json_object_object_add(dev_list_node, "downlink_rssi_v", json_object_new_string(tmp));
			json_object_array_add(dev_list, dev_list_node);
		}
		
	}

	if (json_object_array_length(dev_list) > 0) {
		json_object_object_add(wds_link_qua_obj, "linkStat", json_object_new_string("1"));
	}
	else {
		json_object_object_add(wds_link_qua_obj, "linkStat", json_object_new_string("0"));
	}

	json_object_object_add(wds_link_qua_obj, "devList", dev_list);

	return wds_link_qua_obj;
}


static void wds_linkq_redis_disconnect() {
	if (wds_link_qua_dbs) {
		redbs_finish(wds_link_qua_dbs);
		wds_link_qua_dbs = NULL;
	}
}

static int wdsLinkQuality_get(char** rbuf)
{
	struct json_object *wds_link_qua_json;
	struct wds_info redis_info;
	wds_link_qua_t *obj, *tmp;
	void *arg = NULL;
	char *pbuf;
	int ret;

	wds_link_qua_dbs = redbs_init("WDS_LINK_QUA_REDBS",NULL);
    if (wds_link_qua_dbs == NULL) {
        WDS_LINK_QUA_DEBUG("wds_link_quality redis_init fail!\n");
        return FAIL;
    }

    if (redbs_connect(wds_link_qua_dbs, REDBS_HOST_DB, NULL, arg) != 0) {
        WDS_LINK_QUA_DEBUG("wds_link_quality connect REDBS_NCDB_DB failed!\n");
		ret = -1;
        goto faild_end2;
    }

	memset(dev_sn, 0, sizeof(dev_sn));
	if(get_sn_by_uci(dev_sn, sizeof(dev_sn)) != 0) {
		WDS_LINK_QUA_DEBUG("get sn faild\n");
		ret = -1;
        goto faild_end2;
	}

	redbs_wds_info_get_pub(dev_sn, &redis_info);
	memset(role, 0, sizeof(role));
	strcpy(role, redis_info.role);
	WDS_LINK_QUA_DEBUG("role:%s\n", role);

	if(!strcmp(role, ROLE_IS_AP)) {
		if(ap_get_wds_list_info() != 0) {
			WDS_LINK_QUA_DEBUG("ap_get_wds_list_info faild");
			ret = -2;
			goto faild_end2;
		}
	}
	else {
		if(cpe_get_wds_list_info(dev_sn) != 0) {
			WDS_LINK_QUA_DEBUG("cpe_get_wds_list_info faild");
			ret = -2;
			goto faild_end2;
		}
	}

	wds_link_qua_json = create_wdslinkquality_json();
	if(wds_link_qua_json == NULL) {
		WDS_LINK_QUA_DEBUG("create_wdslinkquality_json faild");
		ret = -3;
		goto faild_end1;
	}

	pbuf = (char *)malloc(PBUF_SIZE);
	if(!pbuf) {
		WDS_LINK_QUA_DEBUG("pbuf malloc memory faild\n");
		ret = -4;
		goto faild_end1;
	}
	*rbuf = pbuf;
	
    strcpy(pbuf, json_object_to_json_string(wds_link_qua_json));
	// WDS_LINK_QUA_DEBUG("wds_link_qua json:%s\n",json_object_to_json_string(wds_link_qua_json));
	ret = 0;

faild_end1:	
	if(wds_link_qua_json != NULL) {
		json_object_put(wds_link_qua_json);
		wds_link_qua_json = NULL;
	}

faild_end2:
	list_for_each_entry_safe(obj,tmp, &wds_link_qua_list, wlq_head) {
		list_del(&obj->wlq_head);
		if(obj != NULL) {
			free(obj);
			obj = NULL;
		}
	}

	wds_linkq_redis_disconnect();
	
	return ret;
}

static int handle_fuc(uf_plugin_attr_t *attr, char **rbuf)  
{
    int ret = 0;  
  
    switch(attr->cmd) {  
	    case(UF_CMD_GET):
			ret = wdsLinkQuality_get(rbuf);
	        break;
	    default:
			WDS_LINK_QUA_DEBUG("<====unsupport cmd====>");
	        break;  
    }
    return ret;  
}  

void module_init_wdslinkquality(uf_plugin_intf_t *intf)  
{  
    strcpy(intf->name, MODULE_NAME);  
    intf->fuc = (uf_handle_fuc)handle_fuc;  
    g_intf = intf;  
    uf_set_plug_debug(g_intf, 0, DEBUG_LOG_SIZE, DEBUG_LOG_LINE_SIZE);
    WDS_LINK_QUA_DEBUG("<======init wdsLinkQuality=========>");  
    return ;  
}  

