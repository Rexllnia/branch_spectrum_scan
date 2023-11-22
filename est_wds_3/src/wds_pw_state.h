#ifndef WDS_PW_STATE_H
#define WDS_PW_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include "wds_gpio_debug.h"


#define MAC_SIZE    6
#define SN_SIZE     14
#define STR_MAC_SIZE     18

#define WDS_PW_INFO_ARR_LEN     5
#define PRINT_MAC(addr)        \
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

#define KEYERR_TYPE_80211              0       //The result of the user entering the cpe password when scanning the ssid follows the 80211 password authentication process
#define KEYERR_TYPE_CUSTOM             1       //Enter the cpe password when the user uses the scanning device

typedef struct key_netlink_info {
    int   wds_pwstat;
	unsigned char   ath_mac[MAC_SIZE];
	unsigned char   sn[SN_SIZE];
	unsigned char   dev_mac[STR_MAC_SIZE];
	unsigned char   keyerr_type;
}wds_pw_info_t;

typedef struct key_netlink_info_arr{
	wds_pw_info_t wds_pw_info_arr[WDS_PW_INFO_ARR_LEN];
	int valid_len;
}wds_pw_info_arr_t;

void wds_pw_arr_update(wds_pw_info_t *wds_pw_node, int index);
void wds_pw_arr_add(wds_pw_info_t *);
void wds_pw_arr_del(int index);
int wds_pw_arr_find_node(char*);
void get_wds_pw_arr_mac(unsigned char* buf, int pw_state, char keyerr_type);
bool get_arr_wds_pwstat(unsigned char keyerr_type);
void wds_pw_arr_init(void);

#endif

