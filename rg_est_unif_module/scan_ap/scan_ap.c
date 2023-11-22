#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <json-c/json.h>
#include "uf_plugin_intf.h"
#include "lib_unifyframe.h"
#include "scan_ap.h"

static int socket_fd;

static uf_plugin_intf_t* g_intf;

#define AP_SCAN_DEBUG(format, ...) do {\
UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\
} while (0)

static void get_wds_bss_info(char* wds_bss, char* radio_name, char* band_support) {
	struct json_object* device_info;
	struct json_object* wireless;
	struct json_object* radiolist;
	struct json_object* radio;
	struct json_object* support_wds;
	int num_radios;
	int i;
	const char* str = NULL;

	device_info = json_object_from_file(DEVICE_INFO_FILE);

	wireless = json_object_object_get(device_info, "wireless");
	radiolist = json_object_object_get(wireless, "radiolist");
	num_radios = json_object_array_length(radiolist);
	for (i = 0; i < num_radios; i++) {
		radio = json_object_array_get_idx(radiolist, i);
		support_wds = json_object_object_get(radio, "support_wds");
		if (strcmp(json_object_get_string(support_wds), "true") == 0) {
			str = json_object_get_string(json_object_object_get(radio, "wds_bss"));
			strncpy(wds_bss, str, strlen(str));
			str = json_object_get_string(json_object_object_get(radio, "name"));
			strncpy(radio_name, str, strlen(str));
			str = json_object_get_string(json_object_object_get(radio, "band_support"));
			strncpy(band_support, str, strlen(str));
		}
	}

	json_object_put(device_info);
	return;

}

static int uci_wireless_get(char* e, char* section, char* output) {
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char buf[64] = { 0 };

	memset(output, 0, sizeof(output));
	ctx = uci_alloc_context();
	AP_SCAN_DEBUG("section:%s\n", section);
	snprintf(buf, sizeof(buf), "wireless.%s.%s", section, e);
	if (UCI_OK != uci_lookup_ptr(ctx, &ptr, buf, true)) {
		uci_free_context(ctx);
		uci_perror(ctx, "lookup failed");
		return -1;
	}
	if (ptr.o) {
		AP_SCAN_DEBUG("%s: %s\n", e, ptr.o->v.string);
		strncpy(output, ptr.o->v.string, strlen(ptr.o->v.string));
	} else {
		AP_SCAN_DEBUG("%s not found\n", e);
		uci_free_context(ctx);
		return -2;
	}
	uci_free_context(ctx);
	return 0;
}

static int iwpriv_set_cmd(char* ifname, char* cmd, int request) {
	char data[255];
	char name[25];
	struct iwreq wrq;
	memset(name, 0, sizeof(name));
	sprintf(name, "%s", ifname);

	memset(data, 0x00, sizeof(data));
	strcpy(data, cmd);

	strcpy(wrq.ifr_name, name);
	wrq.u.data.length = strlen(data) + 1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (ioctl(socket_fd, request, &wrq) != 0) {
		AP_SCAN_DEBUG("ioctl request error!");
		return -1;
	}
	return 0;
}

static char* iwpriv_get_cmd(char* ifname, char* cmd, int request) {
	char* data;
	char name[25];
	struct iwreq wrq;

	memset(name, 0, sizeof(name));
	sprintf(name, "%s", ifname);

	data = (char*) malloc(DATA_BUF_SIZE);
	if (!data) {
		AP_SCAN_DEBUG("malloc memory faild!");
		return NULL;
	}
	memset(data, 0x00, DATA_BUF_SIZE);
	strcpy(data, cmd);

	strcpy(wrq.ifr_name, name);
	wrq.u.data.length = DATA_BUF_SIZE;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (ioctl(socket_fd, request, &wrq) != 0) {
		AP_SCAN_DEBUG("ioctl request error!");
		free(data);
		return NULL;
	}

	if (wrq.u.data.length > 0) {
		return data;
	}

	free(data);
	return NULL;
}

static void get_country_channel_json(char** r, const char* name, const char* param) {
	uf_cmd_msg_t* msg_obj = NULL;
	int ret;
	char* rbuf;

	rbuf = NULL;
	msg_obj = (uf_cmd_msg_t*) malloc(sizeof(uf_cmd_msg_t));
	if (msg_obj == NULL) {
		*r = strdup("memory full!");
		return;
	}

	memset(msg_obj, 0, sizeof(uf_cmd_msg_t));
	msg_obj->ctype = UF_DEV_STA_CALL;         /* �������� ac/dev/.. */
	msg_obj->cmd = "get";
	msg_obj->module = name;
	msg_obj->param = param;

	ret = uf_client_call(msg_obj, &rbuf, NULL);
	if (ret < 0 || rbuf == NULL) {
		*r = strdup("get country channel failed!");
		free(msg_obj);
		if (rbuf) {
			free(rbuf);
		}
		return;
	}

	free(msg_obj);
	*r = rbuf;
	return;
}

static char* get_scan_msg(void) {
	char* scan_msg;
	char* country_chan_json = NULL;
	struct json_object* json_obj;
	struct json_object* chan_json_obj;
	struct json_object* bandwidth;
	char wds_bss[WDS_BSS_BUF];
	char radio_name[WDS_BSS_BUF];
	char band_support[WDS_BSS_BUF];
	char country_code[WDS_BSS_BUF];
	char mode[WDS_BSS_BUF];
	char cmd_buf[256];
	int channel_num = 0;
	int mode_num = 0;
	int delay_time = 0;

	memset(wds_bss, 0, WDS_BSS_BUF);
	memset(radio_name, 0, WDS_BSS_BUF);
	memset(band_support, 0, WDS_BSS_BUF);
	memset(country_code, 0, WDS_BSS_BUF);
	memset(mode, 0, WDS_BSS_BUF);

	get_wds_bss_info(wds_bss, radio_name, band_support);
	AP_SCAN_DEBUG("wds_bss is %s ", wds_bss);
	AP_SCAN_DEBUG("radio_name is %s ", radio_name);
	AP_SCAN_DEBUG("band_support is %s ", band_support);

	if (iwpriv_set_cmd(wds_bss, SET_SCAN_AP_CMD, RTPRIV_IOCTL_SET)) {
		AP_SCAN_DEBUG("iwpriv_set_cmd fun run faild!");
		return NULL;
	}

	uci_wireless_get("country", radio_name, country_code);
	uci_wireless_get("bw", radio_name, mode);
	AP_SCAN_DEBUG("country_code is %s ", country_code);
	AP_SCAN_DEBUG("mode is %s ", mode);

	if (strcmp(mode, "auto") == 0) {                    /* cpe信道为auto，特殊处理*/
		memset(cmd_buf, 0, CMD_BUF_SIZE);
		snprintf(cmd_buf, CMD_BUF_SIZE, "{\"qry_type\":\"bandwidth_list\", \"range\":\"%s\"}", band_support);
		get_country_channel_json(&country_chan_json, "country_channel", cmd_buf);
		json_obj = uf_json_tokener_parse(country_chan_json);
		memset(cmd_buf, 0, CMD_BUF_SIZE);
		snprintf(cmd_buf, CMD_BUF_SIZE, "bandwidth_%s", band_support);
		json_object_object_get_ex(json_obj, cmd_buf, &bandwidth);
		mode_num = json_object_array_length(bandwidth);
		strcpy(mode, json_object_get_string(json_object_array_get_idx(bandwidth, mode_num - 1)));
		
		json_object_put(json_obj);
		free(country_chan_json);
		country_chan_json = NULL;
	}

	memset(cmd_buf, 0, CMD_BUF_SIZE);
	snprintf(cmd_buf, CMD_BUF_SIZE, "{\"qry_type\":\"channellist\",\"country\":\"%s\",\"range\":\"%s\",\"band\":\"BW_%s\"}", country_code, band_support, mode);
	AP_SCAN_DEBUG("cmd_buf is %s", cmd_buf);
	get_country_channel_json(&country_chan_json, "country_channel", cmd_buf);
	AP_SCAN_DEBUG("channel list is %s", country_chan_json);
	chan_json_obj = uf_json_tokener_parse(country_chan_json);
	channel_num = json_object_array_length(chan_json_obj);
	AP_SCAN_DEBUG("channel_num is %d", channel_num);

	json_object_put(country_chan_json);
	free(country_chan_json);
	country_chan_json = NULL;

	delay_time = channel_num - 1;
	sleep(delay_time);

	scan_msg = iwpriv_get_cmd(wds_bss, GET_SCAN_AP_CMD, RTPRIV_IOCTL_GSITESURVEY);
	if (scan_msg == NULL) {
		AP_SCAN_DEBUG("iwpriv_get_cmd fun get scan msg faild!");
		return NULL;
	}
	return scan_msg;
}

static struct json_object* create_scan_ap_json(char* data) {
	struct json_object* scan_ap_json;
	struct json_object* ap_list_array;
	struct json_object* item;

	char ssid[33];
	char tmp_ssid[33];
	char ch[4];
	int tmp_rssi;
	char rssi[10];
	char* token;

	scan_ap_json = json_object_new_object();
	if (scan_ap_json == NULL) {
		AP_SCAN_DEBUG("create scan_ap_json error!");
		return NULL;
	}
	ap_list_array = json_object_new_array();
	if (ap_list_array == NULL) {
		AP_SCAN_DEBUG("create ap_list_array error!");
		return NULL;
	}

	token = strtok(data, "\n");
	if (token != NULL) {
		token = strtok(NULL, "\n");
		if (token != NULL) {
			token = strtok(NULL, "\n");
			if (token != NULL) {
				while (token != NULL) {
					memset(ssid, 0, sizeof(ssid));
					memset(tmp_ssid, 0, sizeof(tmp_ssid));
					sscanf(token, "%*s%s%33[^\n]%*s%*s%d%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s", ch, tmp_ssid, &tmp_rssi);
					sscanf(tmp_ssid, "%s", ssid);
					// AP_SCAN_DEBUG("ch:%s,ssid:%s,rssi:%d", ch, ssid, tmp_rssi);
					item = json_object_new_object();
					if (item == NULL) {
						AP_SCAN_DEBUG("create json item error!");
						continue;
					}
					json_object_object_add(item, "ssid", json_object_new_string(ssid));
					json_object_object_add(item, "channel", json_object_new_string(ch));
					memset(rssi, 0, sizeof(rssi));
					snprintf(rssi, sizeof(rssi), "%d", tmp_rssi + 95);
					json_object_object_add(item, "rssi", json_object_new_string(rssi));
					json_object_array_add(ap_list_array, item);
					token = strtok(NULL, "\n");
				}
			}
		}
	}

	json_object_object_add(scan_ap_json, "ap_list", ap_list_array);

	return scan_ap_json;
}

static int scan_ap_msg_get(char** rbuf) {
	struct json_object* scan_data_json;
	char* scan_data;
	char* pbuf;
	int ret;

	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0) {
		AP_SCAN_DEBUG("create socket error!");
		return -1;
	}

	scan_data = get_scan_msg();
	if (scan_data == NULL) {
		AP_SCAN_DEBUG("scan data is NULL!");
		ret = -1;
		goto filed_end1;
	}

	scan_data_json = create_scan_ap_json(scan_data);
	if (scan_data_json == NULL) {
		AP_SCAN_DEBUG("scan_data_json is NULL!");
		ret = -2;
		goto filed_end2;
	}

	pbuf = (char*) malloc(PBUF_SIZE);
	if (!pbuf) {
		AP_SCAN_DEBUG("pbuf malloc memory faild\n");
		ret = -3;
		goto filed_end2;
	}
	*rbuf = pbuf;

	strcpy(pbuf, json_object_to_json_string(scan_data_json));
	ret = 0;

filed_end2:
	if (scan_data_json != NULL) {
		json_object_put(scan_data_json);
	}

	if (scan_data != NULL) {
		free(scan_data);
	}

filed_end1:
	close(socket_fd);

	return ret;
}

static int handle_fuc(uf_plugin_attr_t* attr, char** rbuf) {
	int ret = 0;

	switch (attr->cmd) {
	case(UF_CMD_GET):
		AP_SCAN_DEBUG("<====start get ap scan msg====>");
		ret = scan_ap_msg_get(rbuf);
		AP_SCAN_DEBUG("<====end get ap scan msg====>");
		break;
	default:
		AP_SCAN_DEBUG("<====unsupport cmd====>");
		break;
	}
	return ret;
}

void module_init_ap_scan(uf_plugin_intf_t* intf) {
	strcpy(intf->name, MODULE_NAEM);
	intf->fuc = (uf_handle_fuc) handle_fuc;
	g_intf = intf;
	uf_set_plug_debug(g_intf, 0, DEBUG_LOG_FILE_SIZE, DEBUG_LOG_LINE_SZIE);
	AP_SCAN_DEBUG("<======init ap_scan=========>");
	return;
}

