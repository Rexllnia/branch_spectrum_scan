#include <string.h>
#include <stdio.h>
#include <json-c/json.h>
#include <libubox/list.h>
#include <hiredis/redbs.h>
#include <hiredis/hiredis.h>
#include <hiredis/redbs_common.h>
#include <hiredis/est/wds/wdsinfo.pb-c.h>
#include "uf_plugin_intf.h"
#include "wds_list_lite.h"

static redbs_t* wds_info_lite_dbs = NULL;
static LIST_HEAD(wds_info_lite_list);
static uf_plugin_intf_t* g_intf;

#define WDS_LITE_DEBUG(format, ...) do {\
    UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\
} while (0)

static void redbs_wds_db2wds_info(WWdsinfo__InfoTable* info_table, struct wds_info* wds_info) {
    strcpy(wds_info->sn, info_table->keys->sn);
    if (info_table->sys_mac != NULL) { strcpy(wds_info->sys_mac, info_table->sys_mac); }
    if (info_table->ath_mac != NULL) { strcpy(wds_info->ath_mac, info_table->ath_mac); }
    if (info_table->peermac != NULL) { strcpy(wds_info->peermac, info_table->peermac); }
    if (info_table->dev_type != NULL) { strcpy(wds_info->dev_type, info_table->dev_type); }
    if (info_table->rssi != NULL) { strcpy(wds_info->rssi, info_table->rssi); }
    if (info_table->channel != NULL) { strcpy(wds_info->channel, info_table->channel); }
    if (info_table->host_name != NULL) { strcpy(wds_info->host_name, info_table->host_name); }
    if (info_table->role != NULL) { strcpy(wds_info->role, info_table->role); }
    if (info_table->rx_speed != NULL) { strcpy(wds_info->rx_speed, info_table->rx_speed); }
    if (info_table->tx_speed != NULL) { strcpy(wds_info->tx_speed, info_table->tx_speed); }
	if (info_table->connecttime != NULL) { strcpy(wds_info->connectTime, info_table->connecttime); }
    if (info_table->networkid != NULL) { strcpy(wds_info->networkid, info_table->networkid); }
    if (info_table->networkname != NULL) { strcpy(wds_info->networkname, info_table->networkname); }
    if (info_table->flag != NULL) { wds_info->flag = info_table->flag; }
    if (info_table->def_pw != NULL) { strcpy(wds_info->def_pw, info_table->def_pw); }
    if (info_table->wds_pw != NULL) { strcpy(wds_info->wds_pw, info_table->wds_pw); }
    if (info_table->wdspw_state != NULL) { strcpy(wds_info->wdspw_state, info_table->wdspw_state); }
    if (info_table->warn_mac != NULL) { strcpy(wds_info->warn_mac, info_table->warn_mac); }
    if (info_table->manage_ssid != NULL) { strcpy(wds_info->manage_ssid, info_table->manage_ssid); }
    if (info_table->manage_bssid != NULL) { strcpy(wds_info->manage_bssid, info_table->manage_bssid); }
    if (info_table->dc_power != NULL) { strcpy(wds_info->dc_power, info_table->dc_power); }
    if (info_table->poe_power != NULL) { strcpy(wds_info->poe_power, info_table->poe_power); }
    if (info_table->rssi_align != NULL) { strcpy(wds_info->rssi_align, info_table->rssi_align); }
    return;
}

static int wds_info_lite_scan_cb(const redbs_t* dbs, redbs_pubsub_msg_t* msg, void* arg) {
    WWdsinfo__InfoTable* info_table;
    WWdsinfo__InfoTableKey* info_key;
    wds_info_lite_t* wds_info_lite;

    if (msg->error != 0) {
        WDS_LITE_DEBUG("error occur %d\n", msg->error);
        return FAIL;
    }

    if (msg->cmd == REDBS_CMD_SCAN) {
        if (msg->flag == 0) {                               /* 数据库开始scan */
            WDS_LITE_DEBUG("[wds_list_lite] start\n");
        } else if (msg->flag == REDBS_SCAN_OVER) {          /* 数据库结束scan */
            WDS_LITE_DEBUG("[wds_list_lite] end\n");
        }
    } else if (msg->cmd == REDBS_CMD_HSET || msg->cmd == REDBS_CMD_SET) {
        info_table = (WWdsinfo__InfoTable*) (msg->value);
        wds_info_lite = (wds_info_lite_t*) malloc(sizeof(wds_info_lite_t));
        if (!wds_info_lite) {
            WDS_LITE_DEBUG("malloc memory faild\n");
            return FAIL;
        }
        memset(wds_info_lite, 0, sizeof(wds_info_lite_t));
        redbs_wds_db2wds_info(info_table, &wds_info_lite->wds_info);

        INIT_LIST_HEAD(&wds_info_lite->wil_head);
        list_add_tail(&wds_info_lite->wil_head, &wds_info_lite_list);
    }

    return SUCCESS;
}

static int get_redis_wds_info_lite(void) {
    WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
    int ret;

    info_table.keys = &info_key;
    ret = redbs_scan(wds_info_lite_dbs, REDBS_HOST_DB, (const redbs_obj*) &info_table, 0, wds_info_lite_scan_cb, NULL);
    return ret;
}

static void rg_wds_json_add_lite_item(wds_info_lite_t* p, struct json_object* item) {
    json_object_object_add(item, "sn", json_object_new_string(p->wds_info.sn));
    json_object_object_add(item, "mac", json_object_new_string(p->wds_info.sys_mac));
    json_object_object_add(item, "rl", json_object_new_string(p->wds_info.role));
    json_object_object_add(item, "dt", json_object_new_string(p->wds_info.dev_type));
    json_object_object_add(item, "nid", json_object_new_string(p->wds_info.networkid));
    json_object_object_add(item, "nn", json_object_new_string(p->wds_info.networkname));
    json_object_object_add(item, "rs", json_object_new_string(p->wds_info.rssi));
    json_object_object_add(item, "ts", json_object_new_string(p->wds_info.tx_speed));
    json_object_object_add(item, "hn", json_object_new_string(p->wds_info.host_name));
    json_object_object_add(item, "ct", json_object_new_string(p->wds_info.connectTime));
    json_object_object_add(item, "ch", json_object_new_string(p->wds_info.channel));
    json_object_object_add(item, "def_pw", json_object_new_boolean(atoi(p->wds_info.def_pw)));
    json_object_object_add(item, "wds_pw", json_object_new_boolean(atoi(p->wds_info.wds_pw)));
    if (strlen(p->wds_info.wdspw_state) == 0) {
        sprintf(p->wds_info.wdspw_state, "%d", "1");   /* 兼容高通旧版本，没有这个信息，代表不支持，默认密码正确 */
    }
    json_object_object_add(item, "wdspw_state", json_object_new_boolean(atoi(p->wds_info.wdspw_state)));
    json_object_object_add(item, "warn_mac", json_object_new_string(p->wds_info.warn_mac));
    json_object_object_add(item, "manage_ssid", json_object_new_string(p->wds_info.manage_ssid));
    json_object_object_add(item, "manage_bssid", json_object_new_string(p->wds_info.manage_bssid));
    if (strlen(p->wds_info.dc_power) == 0) {
        sprintf(p->wds_info.dc_power, "%s", "0");       /* 兼容旧版本，没有这个信息设置为0，0代表不支持dc供电 */
    }
    json_object_object_add(item, "dc_power", json_object_new_boolean(atoi(p->wds_info.dc_power)));
    if (strlen(p->wds_info.poe_power) == 0) {
        sprintf(p->wds_info.poe_power, "%s", "0");      /* 兼容旧版本，没有这个信息设置为0，0代表不支持poe供电 */
    }
    json_object_object_add(item, "poe_power", json_object_new_boolean(atoi(p->wds_info.poe_power)));

    if (strlen(p->wds_info.rssi_align) == 0) {
        sprintf(p->wds_info.rssi_align, "%s", "0");      /* 兼容旧版本，没有这个信息设置为0，0代表不支持rssi对准 */
    }
    json_object_object_add(item, "rssi_align", json_object_new_boolean(atoi(p->wds_info.rssi_align)));
}

static struct json_object* create_wds_info_lite_json(void) {
    struct json_object* file_1;
    struct json_object* section_2;
    struct json_object* section_1;
    struct json_object* file_2;
    struct json_object* item_3;
    struct json_object* item_2;

    wds_info_lite_t* obj1;
    wds_info_lite_t* obj2;

    unsigned int total = 0;
    unsigned int wds_total[4];

    file_1 = json_object_new_object();
    if (file_1 == NULL) {
        WDS_LITE_DEBUG("wrt_info_lite:file_1 is NULL!!!");
        goto end;
    }

    section_2 = json_object_new_array();
    if (section_2 == NULL) {
        json_object_put(file_1);
        WDS_LITE_DEBUG("wrt_info_lite:section_2 is null!!!");
        goto end;
    }

    char flag_free = 0;
    list_for_each_entry(obj1, &wds_info_lite_list, wil_head) {
        total++;
        section_1 = json_object_new_array();
        if (section_1 == NULL) {
            WDS_LITE_DEBUG("wrt_info_lite:section_1 is null !");
            continue;
        }
        file_2 = json_object_new_object();
        if (file_2 == NULL) {
            json_object_put(section_1);
            WDS_LITE_DEBUG("wrt_info_lite:file_2 is null !");
            continue;
        }

        item_3 = json_object_new_object();
        if (item_3 == NULL) {
            json_object_put(section_1);
            json_object_put(file_2);
            WDS_LITE_DEBUG("wrt_info_lite:item_3 is null !");
            continue;
        }

        flag_free = 0;
        if (obj1->wds_info.flag == 0) {
            obj1->wds_info.flag = 1;
        } else {
            flag_free = 1;
            goto loop2;
        }

        if (strcmp("cpe", obj1->wds_info.role) == 0) {
            if (strlen(obj1->wds_info.peermac) == 0) {
                goto loop1;
            }
        }
        list_for_each_entry(obj2, &wds_info_lite_list, wil_head) {
            if (strcmp("ap", obj1->wds_info.role) == 0) {
                if (strlen(obj1->wds_info.ath_mac) != 0) {
                    if ((strncmp(obj1->wds_info.ath_mac, obj2->wds_info.ath_mac, strlen(obj1->wds_info.ath_mac)) == 0 || strncmp(obj1->wds_info.ath_mac, obj2->wds_info.peermac, strlen(obj1->wds_info.ath_mac)) == 0) && obj2->wds_info.flag == 0) {
                        item_2 = json_object_new_object();
                        if (item_2 == NULL) {
                            WDS_LITE_DEBUG("wrt_info_lite:item_2 is null !");
                            continue;
                        }
                        obj2->wds_info.flag = 1;
                        rg_wds_json_add_lite_item(obj2, item_2);
                        json_object_array_add(section_1, item_2);
                    }
                }
            } else {
                if (strlen(obj1->wds_info.peermac) != 0) {
                    if ((strncmp(obj1->wds_info.peermac, obj2->wds_info.ath_mac,strlen(obj1->wds_info.peermac)) == 0 || strncmp(obj1->wds_info.peermac, obj2->wds_info.peermac, strlen(obj1->wds_info.peermac)) == 0) && obj2->wds_info.flag == 0) {
                        item_2 = json_object_new_object();
                        if (item_2 == NULL) {
                            WDS_LITE_DEBUG("wrt_info_lite:item_2 is null !");
                            continue;
                        }
                        obj2->wds_info.flag = 1;
                        rg_wds_json_add_lite_item(obj2, item_2);
                        json_object_array_add(section_1, item_2);
                    }
                }
            }
        }

    loop1:
        rg_wds_json_add_lite_item(obj1, item_3);
        json_object_array_add(section_1, item_3);
        json_object_object_add(file_2, "list_pair", section_1);
        json_object_array_add(section_2, file_2);

    loop2:
        if (flag_free) {
            json_object_put(section_1);
            json_object_put(file_2);
            json_object_put(item_3);
        }
    }

    json_object_object_add(file_1, "list_all", section_2);
    memset(wds_total, 0, sizeof(wds_total));
    snprintf(wds_total, sizeof(wds_total), "%u", total);
    json_object_object_add(file_1, "total", json_object_new_string(wds_total));

    return file_1;

end:
    return NULL;
}

static void wds_lite_redis_disconnect() {
    if (wds_info_lite_dbs) {
        redbs_finish(wds_info_lite_dbs);
        wds_info_lite_dbs = NULL;
    }
}

static int wds_info_lite_get(char** rbuf) {
    struct json_object* wds_info_lite_json;
    void* arg = NULL;
    wds_info_lite_t* obj, * tmp;
    char* pbuf;
    int ret;

    wds_info_lite_dbs = redbs_init("WDS_INFO_LITE_REDBS", NULL);
    if (wds_info_lite_dbs == NULL) {
        WDS_LITE_DEBUG("wds_info_lite redis_init fail!\n");
        return -1;
    }

    if (redbs_connect(wds_info_lite_dbs, REDBS_HOST_DB, NULL, arg) != 0) {
        WDS_LITE_DEBUG("wds_info_lite connect REDBS_NCDB_DB failed!\n");
        wds_lite_redis_disconnect();
        return -1;
    }

    if (get_redis_wds_info_lite() != 0) {
        WDS_LITE_DEBUG("get_redis_wds_info_lite faild");
        ret = -2;
        goto faild_end2;
    }

    wds_info_lite_json = create_wds_info_lite_json();
    if (wds_info_lite_json == NULL) {
        WDS_LITE_DEBUG("create_wds_info_lite_json faild");
        ret = -3;
        goto faild_end1;
    }

    pbuf = (char*) malloc(PBUF_SIZE);
    if (!pbuf) {
        WDS_LITE_DEBUG("pbuf malloc memory faild\n");
        ret = -4;
        goto faild_end1;
    }
    *rbuf = pbuf;

    strcpy(pbuf, json_object_to_json_string(wds_info_lite_json));
    /* WDS_LITE_DEBUG("wds_info_lite json:%s\n",json_object_to_json_string(wds_info_lite_json)); */
    ret = 0;

faild_end1:
    if (wds_info_lite_json != NULL) {
        json_object_put(wds_info_lite_json);
		wds_info_lite_json = NULL;
    }

faild_end2:
    list_for_each_entry_safe(obj, tmp, &wds_info_lite_list, wil_head) {
        list_del(&obj->wil_head);
		if(obj != NULL) {
			free(obj);
			obj = NULL;
		}    
    }

    wds_lite_redis_disconnect();

    return ret;
}

static int handle_fuc(uf_plugin_attr_t* attr, char** rbuf) {
    int ret = 0;

    switch (attr->cmd) {
    case(UF_CMD_GET):
        WDS_LITE_DEBUG("<====start get wds_list_all====>");
        ret = wds_info_lite_get(rbuf);
        WDS_LITE_DEBUG("<====end get wds_list_all====>");
        break;
    default:
        WDS_LITE_DEBUG("<====unsupport cmd====>");
        break;
    }
    return ret;
}

void module_init_wds_info_lite(uf_plugin_intf_t* intf) {
    strcpy(intf->name, MODULE_NAME);
    intf->fuc = (uf_handle_fuc) handle_fuc;
    g_intf = intf;
    uf_set_plug_debug(g_intf, 0, DEBUG_LOG_SIZE, DEBUG_LOG_LINE_SIZE);
    WDS_LITE_DEBUG("<======init wds_info_lite=========>");
    return;
}