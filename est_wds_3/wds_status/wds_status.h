#ifndef __wds_status__
#define __wds_status__

#define DEBUG_LOG_SIZE				4000         		
#define DEBUG_LOG_LINE_SIZE 		1000		  		
#define MODULE_NAME 				"wds_status"
#define FAIL 						-1
#define SUCCESS						0

#define ROLE_IS_AP         			"ap"
#define ROLE_IS_CPE        			"cpe"
#define ATH_MODE_STA                "1" 
#define ATH_MODE_AP                 "0" 
#define MODE_AP                     1
#define MODE_CPE                    0

#define STR_MAC_SIZE     			18
#define WDS_PW_INFO_ARR_LEN     	5

#define UCI_SYSINFO_FILE   			"/etc/config/sysinfo"
#define PBUF_SIZE    				32*10*100
#define ATH_GET_CMD_MODE            "wireless.%s.ApCliEnable"
#define DEV_CAP_DIR   		        "/tmp/rg_device/rg_device.json"
#endif


