#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <json-c/json.h>
#include "uf_plugin_intf.h"
#include "scan_wds_ap.h"

static uf_plugin_intf_t *g_intf;
static int socket_fd;

  
#define SCAN_WDS_AP_DEBUG(format, ...) do {\  
	UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\  
} while(0)  

static struct json_object *create_scan_wds_ap_json()
{
	struct json_object *json_obj;
	json_obj = json_object_from_file("/tmp/wds_scanner_list.json");
	if (json_obj == NULL) {
		SCAN_WDS_AP_DEBUG("get /tmp/wds_scanner_list.json faild!");
		return NULL;
	}
	
	return json_obj;
}

static int scan_wds_ap_msg_get(char** rbuf)
{
	struct json_object *scan_wds_ap_json;
	char *pbuf;

	socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if(socket_fd < 0) {
		SCAN_WDS_AP_DEBUG("create socket error!");
		return -1;
	}

	system("iwpriv rai0 set PartialScan=1 &");
	scan_wds_ap_json = create_scan_wds_ap_json();
	if(scan_wds_ap_json == NULL) {
		SCAN_WDS_AP_DEBUG("get scan_wds_ap_json faild!");
		return -1;
	}

	pbuf = (char *)malloc(PBUF_SIZE);
	if(!pbuf) {
		SCAN_WDS_AP_DEBUG("pbuf malloc memory faild\n");;
		return -1;
	}
	*rbuf = pbuf;

	strcpy(pbuf, json_object_to_json_string(scan_wds_ap_json));

	close(socket_fd);
	
	return 0;
}


static int handle_fuc(uf_plugin_attr_t *attr, char **rbuf)  
{  
	int ret = 0;  

	switch(attr->cmd) {  
		case(UF_CMD_GET):  
			SCAN_WDS_AP_DEBUG("<====start get scan wds ap msg====>");
			ret = scan_wds_ap_msg_get(rbuf);   
			SCAN_WDS_AP_DEBUG("<====end get scan wds ap msg====>");
			break; 
		default:
			SCAN_WDS_AP_DEBUG("<====unsupport cmd====>");
			break;  
	}  
	return ret;  

}  
  
void module_init_scan_wds_ap(uf_plugin_intf_t *intf)  
{  
	strcpy(intf->name, MODULE_NAEM);  
	intf->fuc = (uf_handle_fuc)handle_fuc;  
	g_intf = intf;  
	uf_set_plug_debug(g_intf, 0, DEBUG_LOG_FILE_SIZE, DEBUG_LOG_LINE_SZIE);
	SCAN_WDS_AP_DEBUG("<======init scan_wds_ap=========>");  
	return ;  
}  

