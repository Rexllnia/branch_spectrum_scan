#include <string.h>
#include <stdio.h>
#include <json-c/json.h>
#include <libubox/list.h>
#include <hiredis/redbs.h>
#include <hiredis/hiredis.h>
#include <hiredis/redbs_common.h>
#include <hiredis/est/wds/wdsinfo.pb-c.h>
#include "uf_plugin_intf.h"
#include "wds_list_all.h"

static redbs_t* wds_list_all_dbs = NULL;
static LIST_HEAD(wds_list_all_list);
static uf_plugin_intf_t* g_intf;

#define WDS_LIST_DEBUG(format, ...) do {\
	UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\
} while (0)

static void redbs_wds_db2wds_info(WWdsinfo__InfoTable* info_table, struct wds_info* wds_info) {
	strcpy(wds_info->sn, info_table->keys->sn);
	if (info_table->time_update != NULL) { wds_info->time_update = info_table->time_update; }
	if (info_table->peer_sn != NULL) { strcpy(wds_info->peer_sn, info_table->peer_sn); }
	if (info_table->sys_mac != NULL) { strcpy(wds_info->sys_mac, info_table->sys_mac); }
	if (info_table->ath_mac != NULL) { strcpy(wds_info->ath_mac, info_table->ath_mac); }
	if (info_table->peermac != NULL) { strcpy(wds_info->peermac, info_table->peermac); }
	if (info_table->dev_type != NULL) { strcpy(wds_info->dev_type, info_table->dev_type); }
	if (info_table->ipaddr != NULL) { strcpy(wds_info->ipaddr, info_table->ipaddr); }
	if (info_table->netmask != NULL) { strcpy(wds_info->netmask, info_table->netmask); }
	if (info_table->time != NULL) { strcpy(wds_info->time, info_table->time); }
	if (info_table->band != NULL) { strcpy(wds_info->band, info_table->band); }
	if (info_table->rssi != NULL) { strcpy(wds_info->rssi, info_table->rssi); }
	if (info_table->rssi_a != NULL) { strcpy(wds_info->rssi_a, info_table->rssi_a); }
	if (info_table->rate != NULL) { strcpy(wds_info->rate, info_table->rate); }
	if (info_table->channel != NULL) { strcpy(wds_info->channel, info_table->channel); }
	if (info_table->passwd != NULL) { strcpy(wds_info->passwd, info_table->passwd); }
	if (info_table->channf != NULL) { strcpy(wds_info->channf, info_table->channf); }
	if (info_table->chutil != NULL) { strcpy(wds_info->chutil, info_table->chutil); }
	if (info_table->chutil_a != NULL) { strcpy(wds_info->chutil_a, info_table->chutil_a); }
	if (info_table->phymode != NULL) { strcpy(wds_info->phymode, info_table->phymode); }
	if (info_table->host_name != NULL) { strcpy(wds_info->host_name, info_table->host_name); }
	if (info_table->role != NULL) { strcpy(wds_info->role, info_table->role); }
	if (info_table->lock != NULL) { strcpy(wds_info->lock, info_table->lock); }
	if (info_table->onlinestatus != NULL) { strcpy(wds_info->onlinestatus, info_table->onlinestatus); }
	if (info_table->cwmp != NULL) { strcpy(wds_info->cwmp, info_table->cwmp); }
	if (info_table->lan1speed != NULL) { strcpy(wds_info->lan1speed, info_table->lan1speed); }
	if (info_table->lan1link != NULL) { strcpy(wds_info->lan1link, info_table->lan1link); }
	if (info_table->lan1duplex != NULL) { strcpy(wds_info->lan1duplex, info_table->lan1duplex); }
	if (info_table->lan1nosupport != NULL) { strcpy(wds_info->lan1nosupport, info_table->lan1nosupport); }
	if (info_table->lan2speed != NULL) { strcpy(wds_info->lan2speed, info_table->lan2speed); }
	if (info_table->lan2link != NULL) { strcpy(wds_info->lan2link, info_table->lan2link); }
	if (info_table->lan2duplex != NULL) { strcpy(wds_info->lan2duplex, info_table->lan2duplex); }
	if (info_table->lan2nosupport != NULL) { strcpy(wds_info->lan2nosupport, info_table->lan2nosupport); }
	if (info_table->rx_rate != NULL) { strcpy(wds_info->rx_rate, info_table->rx_rate); }
	if (info_table->tx_rate != NULL) { strcpy(wds_info->tx_rate, info_table->tx_rate); }
	if (info_table->rx_speed != NULL) { strcpy(wds_info->rx_speed, info_table->rx_speed); }
	if (info_table->tx_speed != NULL) { strcpy(wds_info->tx_speed, info_table->tx_speed); }
	if (info_table->rx_speed_a != NULL) { strcpy(wds_info->rx_speed_a, info_table->rx_speed_a); }
	if (info_table->tx_speed_a != NULL) { strcpy(wds_info->tx_speed_a, info_table->tx_speed_a); }
	if (info_table->ssid != NULL) { strcpy(wds_info->ssid, info_table->ssid); }
	if (info_table->software_version != NULL) { strcpy(wds_info->software_version, info_table->software_version); }
	if (info_table->softver_new != NULL) { strcpy(wds_info->softver_new, info_table->softver_new); }
	if (info_table->clean_sftn != NULL) { strcpy(wds_info->clean_sftn, info_table->clean_sftn); }
	if (info_table->hardware_version != NULL) { strcpy(wds_info->hardware_version, info_table->hardware_version); }
	if (info_table->wds_tpye != NULL) { strcpy(wds_info->wds_tpye, info_table->wds_tpye); }
	if (info_table->wds_distance != NULL) { strcpy(wds_info->wds_distance, info_table->wds_distance); }
	if (info_table->wds_txpower != NULL) { strcpy(wds_info->wds_txpower, info_table->wds_txpower); }
	if (info_table->nf != NULL) { wds_info->nf = info_table->nf; }
	if (info_table->channel_use != NULL) { wds_info->channel_use = info_table->channel_use; }
	if (info_table->pingtime != NULL) { strcpy(wds_info->pingTime, info_table->pingtime); }
	if (info_table->connecttime != NULL) { strcpy(wds_info->connectTime, info_table->connecttime); }
	if (info_table->networkid != NULL) { strcpy(wds_info->networkid, info_table->networkid); }
	if (info_table->networkname != NULL) { strcpy(wds_info->networkname, info_table->networkname); }
	if (info_table->country != NULL) { strcpy(wds_info->country, info_table->country); }
	if (info_table->flag != NULL) { wds_info->flag = info_table->flag; }
	if (info_table->dfs_ch != NULL) { wds_info->dfs_ch = info_table->dfs_ch; }
	if (info_table->dfs_time != NULL) { strcpy(wds_info->dfs_time, info_table->dfs_time); }
	if (info_table->def_pw != NULL) { strcpy(wds_info->def_pw, info_table->def_pw); }
	if (info_table->wds_pw != NULL) { strcpy(wds_info->wds_pw, info_table->wds_pw); }
	if (info_table->wdspw_state != NULL) { strcpy(wds_info->wdspw_state, info_table->wdspw_state); }
	if (info_table->warn_mac != NULL) { strcpy(wds_info->warn_mac, info_table->warn_mac); }
	if (info_table->scan_dev_cap != NULL) { strcpy(wds_info->scan_dev_cap, info_table->scan_dev_cap); }
	if (info_table->scan_pw_state != NULL) { strcpy(wds_info->scan_pw_state, info_table->scan_pw_state); }
	if (info_table->scan_warn_mac != NULL) { strcpy(wds_info->scan_warn_mac, info_table->scan_warn_mac); }
	if (info_table->manage_ssid != NULL) { strcpy(wds_info->manage_ssid, info_table->manage_ssid); }
	if (info_table->manage_bssid != NULL) { strcpy(wds_info->manage_bssid, info_table->manage_bssid); }
	if (info_table->dc_power != NULL) { strcpy(wds_info->dc_power, info_table->dc_power); }
	if (info_table->poe_power != NULL) { strcpy(wds_info->poe_power, info_table->poe_power); }
	if (info_table->distance_max != NULL) { strcpy(wds_info->distance_max, info_table->distance_max); }
	if (info_table->distance_def != NULL) { strcpy(wds_info->distance_def, info_table->distance_def); }
	if (info_table->automatic_range != NULL) { strcpy(wds_info->automatic_range, info_table->automatic_range); }
	if (info_table->wan_speed_cap != NULL) { strcpy(wds_info->wan_speed_cap, info_table->wan_speed_cap); }
    if (info_table->rssi_align != NULL) { strcpy(wds_info->rssi_align, info_table->rssi_align); }
	return;
}

static int wds_list_all_scan_cb(const redbs_t* dbs, redbs_pubsub_msg_t* msg, void* arg) {
	WWdsinfo__InfoTable* info_table;
	WWdsinfo__InfoTableKey* info_key;
	wds_list_all_t* wds_list_all;

	if (msg->error != 0) {
		WDS_LIST_DEBUG("error occur %d\n", msg->error);
		return FAIL;
	}

	if (msg->cmd == REDBS_CMD_SCAN) {
		if (msg->flag == 0) {   							/* 开始scan */
			WDS_LIST_DEBUG("[wds_list_all] start\n");
		} else if (msg->flag == REDBS_SCAN_OVER) {  		/* 结束scan */
			WDS_LIST_DEBUG("[wds_list_all] end\n");
		}
	} else if (msg->cmd == REDBS_CMD_HSET || msg->cmd == REDBS_CMD_SET) {
		info_table = (WWdsinfo__InfoTable*) (msg->value);
		wds_list_all = (wds_list_all_t*) malloc(sizeof(wds_list_all_t));
		if (!wds_list_all) {
			WDS_LIST_DEBUG("malloc memory faild\n");
			return FAIL;
		}
		memset(wds_list_all, 0, sizeof(wds_list_all_t));
		redbs_wds_db2wds_info(info_table, &wds_list_all->wds_info);

		INIT_LIST_HEAD(&wds_list_all->wla_head);
		list_add_tail(&wds_list_all->wla_head, &wds_list_all_list);
	}

	return SUCCESS;
}

static int get_wds_list_all(void) {
	WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
	WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
	int ret;

	info_table.keys = &info_key;
	ret = redbs_scan(wds_list_all_dbs, REDBS_HOST_DB, (const redbs_obj*) &info_table, 0, wds_list_all_scan_cb, NULL);
	return ret;
}

static void str_split_to_json_arr(struct json_object* j_array, char* arr_name, char* src, const char* delim) {
	char tmp[(STR_MAC_SIZE - 1) * WDS_PW_INFO_ARR_LEN + (WDS_PW_INFO_ARR_LEN - 1) + 1];
	char* token;

	memset(tmp, 0, sizeof(tmp));
	strncpy(tmp, src, sizeof(tmp));

	token = strtok(tmp, delim);

	while (token != NULL) {
		json_object_array_add(j_array, json_object_new_string(token));
		token = strtok(NULL, delim);
	}
}

static void rg_wds_json_add_item(wds_list_all_t* p, struct json_object* item, struct json_object* j_array) {
	char tmp[64];
	json_object* arr, * scanPwWarnMac;
	json_object_object_add(item, "sn", json_object_new_string(p->wds_info.sn));
	json_object_object_add(item, "mac", json_object_new_string(p->wds_info.sys_mac));
	json_object_object_add(item, "ssid", json_object_new_string(p->wds_info.ssid));
	memset(tmp, 0, sizeof(tmp));
	if (strcmp(p->wds_info.softver_new, "clean") == 0 || strcmp(p->wds_info.clean_sftn, "1") == 0) { /* 收到的softver_new为clean的R221版本或者clean_sftn为1的R96.2版本，说明需要清空sofver_new中残留的ReyeeOS,不再有ReyeeOS版本号 */
		memset(p->wds_info.softver_new, 0, sizeof(p->wds_info.softver_new));
	}
	/* 兼容qca旧版本，当没有ReyeeOS 1.58.1912时和以前一样  */
	if (strlen(p->wds_info.softver_new) != 0) {
		strcat(tmp, p->wds_info.softver_new);
		strcat(tmp, ";");
	}
	strcat(tmp, p->wds_info.software_version);
	json_object_object_add(item, "softversion", json_object_new_string(tmp));
	json_object_object_add(item, "role", json_object_new_string(p->wds_info.role));
	json_object_object_add(item, "userIp", json_object_new_string(p->wds_info.ipaddr));
	json_object_object_add(item, "peersn", json_object_new_string(p->wds_info.peer_sn));
	json_object_object_add(item, "userIp", json_object_new_string(p->wds_info.ipaddr));
	json_object_object_add(item, "onlineTime", json_object_new_string(p->wds_info.time));
	json_object_object_add(item, "band", json_object_new_string(p->wds_info.band));
	json_object_object_add(item, "rssi", json_object_new_string(p->wds_info.rssi));
	json_object_object_add(item, "rssi_a", json_object_new_string(p->wds_info.rssi_a));
	json_object_object_add(item, "rxrate", json_object_new_string(p->wds_info.rate));
	json_object_object_add(item, "channel", json_object_new_string(p->wds_info.channel));
	json_object_object_add(item, "passwd", json_object_new_string(p->wds_info.passwd));
	json_object_object_add(item, "channf", json_object_new_string(p->wds_info.channf));
	json_object_object_add(item, "chutil", json_object_new_string(p->wds_info.chutil));
	json_object_object_add(item, "chutil_a", json_object_new_string(p->wds_info.chutil_a));
	json_object_object_add(item, "distance", json_object_new_string(p->wds_info.wds_distance));
	json_object_object_add(item, "txpower", json_object_new_string(p->wds_info.wds_txpower));
	json_object_object_add(item, "phymode", json_object_new_string(p->wds_info.phymode));
	json_object_object_add(item, "netmask", json_object_new_string(p->wds_info.netmask));
	json_object_object_add(item, "lock", json_object_new_string(p->wds_info.lock));
	json_object_object_add(item, "cwmp", json_object_new_string(p->wds_info.cwmp));
	json_object_object_add(item, "lan1speed", json_object_new_string(p->wds_info.lan1speed));
	json_object_object_add(item, "lan1link", json_object_new_string(p->wds_info.lan1link));
	json_object_object_add(item, "lan1duplex", json_object_new_string(p->wds_info.lan1duplex));
	json_object_object_add(item, "lan1nosupport", json_object_new_boolean(atoi(p->wds_info.lan1nosupport)));
	json_object_object_add(item, "lan2speed", json_object_new_string(p->wds_info.lan2speed));
	json_object_object_add(item, "lan2link", json_object_new_string(p->wds_info.lan2link));
	json_object_object_add(item, "lan2duplex", json_object_new_string(p->wds_info.lan2duplex));
	json_object_object_add(item, "lan2nosupport", json_object_new_boolean(atoi(p->wds_info.lan2nosupport)));
	json_object_object_add(item, "hostname", json_object_new_string(p->wds_info.host_name));
	json_object_object_add(item, "onlinestatus", json_object_new_string(p->wds_info.onlinestatus));
	json_object_object_add(item, "rx_rate", json_object_new_string(p->wds_info.rx_rate));
	json_object_object_add(item, "tx_rate", json_object_new_string(p->wds_info.tx_rate));
	json_object_object_add(item, "dev_type", json_object_new_string(p->wds_info.dev_type));
	json_object_object_add(item, "peermac", json_object_new_string(p->wds_info.peermac));
	json_object_object_add(item, "athmac", json_object_new_string(p->wds_info.ath_mac));
	json_object_object_add(item, "hardversion", json_object_new_string(p->wds_info.hardware_version));
	json_object_object_add(item, "rx_speed", json_object_new_string(p->wds_info.rx_speed));
	json_object_object_add(item, "tx_speed", json_object_new_string(p->wds_info.tx_speed));
	json_object_object_add(item, "rx_speed_a", json_object_new_string(p->wds_info.rx_speed_a));
	json_object_object_add(item, "tx_speed_a", json_object_new_string(p->wds_info.tx_speed_a));
	json_object_object_add(item, "pingTime", json_object_new_string(p->wds_info.pingTime));
	json_object_object_add(item, "connectTime", json_object_new_string(p->wds_info.connectTime));

	json_object_object_add(item, "networkId", json_object_new_string(p->wds_info.networkid));
	json_object_object_add(item, "networkName", json_object_new_string(p->wds_info.networkname));

	json_object_object_add(item, "country", json_object_new_string(p->wds_info.country));

	memset(tmp, 0, sizeof(tmp));
	sprintf(tmp, "%d", p->wds_info.dfs_ch);
	json_object_object_add(item, "dch", json_object_new_string(tmp));
	json_object_object_add(item, "dtm", json_object_new_string(p->wds_info.dfs_time));
	json_object_object_add(item, "def_pw", json_object_new_boolean(atoi(p->wds_info.def_pw)));
	json_object_object_add(item, "wds_pw", json_object_new_boolean(atoi(p->wds_info.wds_pw)));
	if (strlen(p->wds_info.wdspw_state) == 0) {
		sprintf(p->wds_info.wdspw_state, "%s", "1");				/* 兼容高通旧版本，没有这个信息，代表不支持，默认密码正确  */
	}
	json_object_object_add(item, "wdspw_state", json_object_new_boolean(atoi(p->wds_info.wdspw_state)));
	if (strcmp(p->wds_info.wdspw_state, "1") == 0) {
		WDS_LIST_DEBUG("wdspw right clean warn_mac");
		memset(p->wds_info.warn_mac, 0, sizeof(p->wds_info.warn_mac));		/* 当密码正确时清空warn_mac */
	}
	json_object_object_add(item, "warn_mac", json_object_new_string(p->wds_info.warn_mac));
	if (strlen(p->wds_info.dc_power) == 0) {
		sprintf(p->wds_info.dc_power, "%s", "0");				/*兼容旧版本，没有这个信息设置为0，0代表不支持dc供电 */
	}
	json_object_object_add(item, "dc_power", json_object_new_boolean(atoi(p->wds_info.dc_power)));
	if (strlen(p->wds_info.poe_power) == 0) {
		sprintf(p->wds_info.poe_power, "%s", "0");				/* 兼容旧版本，没有这个信息设置为0，0代表不支持poe供电 */
	}
	json_object_object_add(item, "poe_power", json_object_new_boolean(atoi(p->wds_info.poe_power)));

	if (strlen(p->wds_info.rssi_align) == 0) {
		sprintf(p->wds_info.rssi_align, "%s", "0");
	}
	json_object_object_add(item, "rssi_align", json_object_new_boolean(atoi(p->wds_info.rssi_align)));

	if (strlen(p->wds_info.distance_max) == 0) {
		sprintf(p->wds_info.distance_max, "%s", "0");			/*兼容旧版本，没有这个信息设置为0，0代表不支持从wds_list_all接口获取距离值 */
	}
	json_object_object_add(item, "distance_max", json_object_new_string(p->wds_info.distance_max));

	if (strlen(p->wds_info.distance_def) == 0) {
		sprintf(p->wds_info.distance_def, "%s", "0");			/* 兼容旧版本，没有这个信息设置为0，0代表不支持从wds_list_all接口获取距离值 */
	}
	json_object_object_add(item, "distance_def", json_object_new_string(p->wds_info.distance_def));

	if (strlen(p->wds_info.automatic_range) == 0) {
		sprintf(p->wds_info.automatic_range, "%s", "0");			/*兼容旧版本，没有这个信息设置为0，0代表不支持自动测距(以前的设备都不支持自动测距) */
	}
	json_object_object_add(item, "automatic_range", json_object_new_boolean(atoi(p->wds_info.automatic_range)));

	if (strlen(p->wds_info.wan_speed_cap) == 0) {
		memset(p->wds_info.wan_speed_cap, 0, sizeof(p->wds_info.wan_speed_cap));
		WDS_LIST_DEBUG("sn:%s without wan_speed_cap def wanSpeedCap=100", p->wds_info.sn);
		memcpy(p->wds_info.wan_speed_cap, "100", 3); 				/* 兼容旧设备，没有接收wan_speed和原来保持一致100M */
	}
	json_object_object_add(item, "wanSpeedCap", json_object_new_string(p->wds_info.wan_speed_cap));

	json_object_object_add(item, "scanDevCap", json_object_new_boolean(atoi(p->wds_info.scan_dev_cap)));
	if (strlen(p->wds_info.scan_pw_state) == 0) {
		sprintf(p->wds_info.scan_pw_state, "%s", "1");   			/* 兼容R228以前的旧版本，没有这个信息，代表不支持，默认扫描密码正确 */
	}
	json_object_object_add(item, "scanPwStat", json_object_new_boolean(atoi(p->wds_info.scan_pw_state)));

	if (strcmp(p->wds_info.scan_pw_state, "1") == 0) {
		WDS_LIST_DEBUG("scan_pw_state right clean scan_warn_mac");
		memset(p->wds_info.scan_warn_mac, 0, sizeof(p->wds_info.scan_warn_mac));   /* 当扫描设备密码正确时清空scan_warn_mac */
	}

	if (strlen(p->wds_info.scan_warn_mac)) {
		str_split_to_json_arr(j_array, "scanPwWarnMac", p->wds_info.scan_warn_mac, "-");
	}
	json_object_object_add(item, "scanPwWarnMac", j_array);
	json_object_object_add(item, "virtual", json_object_new_boolean(0));
}

static struct json_object* create_wds_info_list_json(void) {
	struct json_object* file_1;
	struct json_object* section_2;
	struct json_object* section_1;
	struct json_object *file_2;
	struct json_object* item_3;
	struct json_object* j_array3;
	struct json_object* item_2;
	struct json_object* j_array2;
	wds_list_all_t* obj1;
	wds_list_all_t* obj2;

	unsigned int total = 0;
	unsigned int wds_total[4];

	file_1 = json_object_new_object();
	if (file_1 == NULL) {
		WDS_LIST_DEBUG("create_wds_info_list_json:file_1 is NULL!!!");
		goto end;
	}

	section_2 = json_object_new_array();
	if (section_2 == NULL) {
		json_object_put(file_1);
		WDS_LIST_DEBUG("create_wds_info_list_json:section_2 is null!!!");
		goto end;
	}

	char flag_free = 0;
	list_for_each_entry(obj1, &wds_list_all_list, wla_head) {
		total++;
		section_1 = json_object_new_array();
		if (section_1 == NULL) {
			WDS_LIST_DEBUG("create_wds_info_list_json:section_1 is null !");
			continue;
		}
		file_2 = json_object_new_object();
		if (file_2 == NULL) {
			json_object_put(section_1);
			WDS_LIST_DEBUG("create_wds_info_list_json:file_2 is null !");
			continue;
		}

		item_3 = json_object_new_object();
		if (item_3 == NULL) {
			json_object_put(section_1);
			json_object_put(file_2);
			WDS_LIST_DEBUG("create_wds_info_list_json:item_3 is null !");
			continue;
		}

		j_array3 = json_object_new_array();
		if (j_array3 == NULL) {
			json_object_put(section_1);
			json_object_put(file_2);
			json_object_put(item_3);
			WDS_LIST_DEBUG("create_wds_info_list_json:j_array3 is null !");
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
		list_for_each_entry(obj2, &wds_list_all_list, wla_head) {
			if (strcmp("ap", obj1->wds_info.role) == 0) {
				if (strlen(obj1->wds_info.ath_mac) != 0) {
					if ((strncmp(obj1->wds_info.ath_mac, obj2->wds_info.ath_mac, strlen(obj1->wds_info.ath_mac)) == 0 || strncmp(obj1->wds_info.ath_mac, obj2->wds_info.peermac, strlen(obj1->wds_info.ath_mac)) == 0) && obj2->wds_info.flag == 0) {
						item_2 = json_object_new_object();
						if (item_2 == NULL) {
							WDS_LIST_DEBUG("create_wds_info_list_json:item_2 is null !");
							continue;
						}
						j_array2 = json_object_new_array();
						if (j_array2 == NULL) {
							WDS_LIST_DEBUG("create_wds_info_list_json:j_array2 is null !");
							continue;
						}
						obj2->wds_info.flag = 1;
						rg_wds_json_add_item(obj2, item_2, j_array2);
						json_object_array_add(section_1, item_2);
					}
				}
			} else {
				if (strlen(obj1->wds_info.peermac) != 0) {
					if ((strncmp(obj1->wds_info.peermac, obj2->wds_info.ath_mac, strlen(obj1->wds_info.peermac)) == 0 || strncmp(obj1->wds_info.peermac, obj2->wds_info.peermac, strlen(obj1->wds_info.peermac)) == 0) && obj2->wds_info.flag == 0) {
						item_2 = json_object_new_object();
						if (item_2 == NULL) {
							WDS_LIST_DEBUG("create_wds_info_list_json:item_2 is null !");
							continue;
						}
						j_array2 = json_object_new_array();
						if (j_array2 == NULL) {
							WDS_LIST_DEBUG("create_wds_info_list_json:j_array2 is null !");
							continue;
						}
						obj2->wds_info.flag = 1;
						rg_wds_json_add_item(obj2, item_2, j_array2);
						json_object_array_add(section_1, item_2);
					}
				}
			}
		}

	loop1:
		rg_wds_json_add_item(obj1, item_3, j_array3);
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
	}

	json_object_object_add(file_1, "list_all", section_2);
	memset(wds_total, 0, sizeof(wds_total));
	snprintf(wds_total, sizeof(wds_total), "%u", total);
	json_object_object_add(file_1, "total", json_object_new_string(wds_total));

	return file_1;

end:
	return NULL;
}

static void wds_all_redis_disconnect() {
	if (wds_list_all_dbs) {
		redbs_finish(wds_list_all_dbs);
		wds_list_all_dbs = NULL;
	}
}

static struct json_object* create_wds_list_pair_json(char *devsn) {
	struct json_object* list_pair;
	struct json_object* list_pair_item;
	struct json_object* list_pair_array;
	struct json_object* j_array;
	wds_list_all_t* obj;
	wds_list_all_t* obj1;
	unsigned char peersn[30];
	int role = 0;

	list_pair = json_object_new_object();
	if (list_pair == NULL) {
		WDS_LIST_DEBUG("create_wds_list_pair_json:list_pair is NULL!!!");
		return NULL;
	}

	list_pair_array = json_object_new_array();
	if (list_pair_array == NULL) {
		json_object_put(list_pair);
		WDS_LIST_DEBUG("create_wds_list_pair_json:list_pair_array is null!!!");
		return NULL;
	}

	memset(peersn, 0, sizeof(peersn));
	
	list_for_each_entry(obj1, &wds_list_all_list, wla_head) {
		if(strncmp(obj1->wds_info.sn, devsn, strlen(devsn)) == 0) {
			if(strcmp(obj1->wds_info.role, "cpe") == 0) {
				role = 1;										/* cpe */
				if(strlen(obj1->wds_info.peer_sn) != 0) {
					strcpy(peersn, obj1->wds_info.peer_sn);
				}
				else{
					list_pair_item = json_object_new_object();
					if (list_pair_item == NULL) {
						WDS_LIST_DEBUG("create_wds_list_pair_json:list_pair_item is null !");
						json_object_put(list_pair);
						json_object_put(list_pair_array);
						return NULL;
					}
					j_array = json_object_new_array();
					if (j_array == NULL) {
						WDS_LIST_DEBUG("create_wds_list_pair_json:j_array is null !");
						json_object_put(list_pair);
						json_object_put(list_pair_array);
						json_object_put(j_array);
						return NULL;
					}
					rg_wds_json_add_item(obj1, list_pair_item, j_array);
					json_object_array_add(list_pair_array, list_pair_item);
					goto loop;
				}
			}
			else{
				role = 0;                                		/* ap */
			}
			break;
		}
		else{
			role = -1;                                   		/* sn not find */
		}
	}
	
	if(role == 1) {                              /* cpe */
		list_for_each_entry(obj, &wds_list_all_list, wla_head) {
			if(strncmp(obj->wds_info.sn, peersn, strlen(peersn)) == 0 || strncmp(obj->wds_info.peer_sn, peersn, strlen(peersn)) == 0) {
				list_pair_item = json_object_new_object();
				if (list_pair_item == NULL) {
					WDS_LIST_DEBUG("create_wds_list_pair_json:list_pair_item is null !");
					continue;
				}
				j_array = json_object_new_array();
				if (j_array == NULL) {
					WDS_LIST_DEBUG("create_wds_list_pair_json:j_array is null !");
					continue;
				}
				rg_wds_json_add_item(obj, list_pair_item, j_array);
				json_object_array_add(list_pair_array, list_pair_item);
			}
		}	
	}
	else if(role == 0) {						/* ap */
		list_for_each_entry(obj, &wds_list_all_list, wla_head) {
			if(strncmp(obj->wds_info.sn, devsn, strlen(devsn)) == 0 || strncmp(obj->wds_info.peer_sn, devsn, strlen(devsn)) == 0) {
				list_pair_item = json_object_new_object();
				if (list_pair_item == NULL) {
					WDS_LIST_DEBUG("create_wds_list_pair_json:list_pair_item is null !");
					continue;
				}
				j_array = json_object_new_array();
				if (j_array == NULL) {
					WDS_LIST_DEBUG("create_wds_list_pair_json:j_array is null !");
					continue;
				}
				rg_wds_json_add_item(obj, list_pair_item, j_array);
				json_object_array_add(list_pair_array, list_pair_item);
			}
		}
	}
	else{
		WDS_LIST_DEBUG("create_wds_list_pair_json:this device sn is not in the list");
		json_object_put(list_pair_array);
		json_object_put(list_pair);
		return NULL;
	}

loop:
	json_object_object_add(list_pair, "list_pair", list_pair_array);

	return list_pair;
}

static int wds_list_all_get(struct json_object *json_obj, char** rbuf) {
	struct json_object *wds_list_all_info_json = NULL;
	char *devsn;
	char dev_sn[30];
	void* arg = NULL;
	wds_list_all_t* obj, * tmp;
	char* pbuf;
	int ret;

	wds_list_all_dbs = redbs_init("WDS_LIST_ALL_REDBS", NULL);
	if (wds_list_all_dbs == NULL) {
		WDS_LIST_DEBUG("wds_list_all redis_init fail!\n");
		return -1;
	}

	if (redbs_connect(wds_list_all_dbs, REDBS_HOST_DB, NULL, arg) != 0) {
		WDS_LIST_DEBUG("wds_list_all connect REDBS_NCDB_DB failed!\n");
		wds_all_redis_disconnect();
		return -1;
	}

	if (get_wds_list_all() != 0) {
		WDS_LIST_DEBUG("get_wds_list_all faild");
		ret = -2;
		goto faild_end2;
	}

	pbuf = (char*) malloc(PBUF_SIZE);
	if (!pbuf) {
		WDS_LIST_DEBUG("pbuf malloc memory faild\n");
		ret = -3;
		goto faild_end1;
	}
	*rbuf = pbuf;

	memset(dev_sn, 0, sizeof(dev_sn));
	if(json_obj != NULL) {
		devsn = json_object_get_string(json_object_object_get(json_obj, "devSn"));
		strncpy(dev_sn, devsn, strlen(devsn));
		if(strlen(dev_sn) != 13) 
		{
			WDS_LIST_DEBUG("the device sn is invalid,sn len is %d", strlen(dev_sn));
			strcpy(pbuf, "");
			ret = -4;
			goto faild_end1;
		}
		else{
			wds_list_all_info_json = create_wds_list_pair_json(dev_sn);
			if(wds_list_all_info_json == NULL) {
				ret = -4;
				strcpy(pbuf, "");
				goto faild_end1;
			}
		}
	}
	else{
		wds_list_all_info_json = create_wds_info_list_json();
		if (wds_list_all_info_json == NULL) {
			WDS_LIST_DEBUG("create_wds_list_all_json faild");
			ret = -4;
			strcpy(pbuf, "");
			goto faild_end1;
		}
	}
	
	strcpy(pbuf, json_object_to_json_string(wds_list_all_info_json));
	ret = 0;

faild_end1:
	if (wds_list_all_info_json != NULL) {
		json_object_put(wds_list_all_info_json);
		wds_list_all_info_json = NULL;
	}

faild_end2:
	list_for_each_entry_safe(obj, tmp, &wds_list_all_list, wla_head) {
		list_del(&obj->wla_head);
		if(obj != NULL) {
			free(obj);
			obj = NULL;
		} 
	}

	wds_all_redis_disconnect();

	return ret;
}

static int handle_fuc(uf_plugin_attr_t* attr, char** rbuf) {
	int ret = 0;

	switch (attr->cmd) {
	case(UF_CMD_GET):
		WDS_LIST_DEBUG("<====start get wds_list_all====>");
		ret = wds_list_all_get(attr->para_obj, rbuf);
		WDS_LIST_DEBUG("<====end get wds_list_all====>");
		break;
	default:
		WDS_LIST_DEBUG("<====unsupport cmd====>");
		break;
	}
	return ret;
}

void module_init_wds_list_all(uf_plugin_intf_t* intf) {
	strcpy(intf->name, MODULE_NAME);
	intf->fuc = (uf_handle_fuc) handle_fuc;
	g_intf = intf;
	uf_set_plug_debug(g_intf, 0, DEBUG_LOG_SIZE, DEBUG_LOG_LINE_SIZE);
	WDS_LIST_DEBUG("<======init wds_list_all=========>");
	return;
}

