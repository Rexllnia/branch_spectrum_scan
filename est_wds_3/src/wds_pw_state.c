#include "wds_pw_state.h"

static wds_pw_info_arr_t wds_pw_stat_arr;

void wds_pw_arr_update(wds_pw_info_t *wds_pw_node, int index){
	wds_pw_stat_arr.wds_pw_info_arr[index].wds_pwstat = wds_pw_node->wds_pwstat;
	wds_pw_stat_arr.wds_pw_info_arr[index].keyerr_type = wds_pw_node->keyerr_type;
	memcpy(wds_pw_stat_arr.wds_pw_info_arr[index].dev_mac , wds_pw_node->dev_mac, STR_MAC_SIZE);
}

void wds_pw_arr_add(wds_pw_info_t *wds_pw_node){
	wds_pw_stat_arr.wds_pw_info_arr[wds_pw_stat_arr.valid_len].wds_pwstat = wds_pw_node->wds_pwstat;
	wds_pw_stat_arr.wds_pw_info_arr[wds_pw_stat_arr.valid_len].keyerr_type = wds_pw_node->keyerr_type;
	memcpy(wds_pw_stat_arr.wds_pw_info_arr[wds_pw_stat_arr.valid_len].dev_mac, wds_pw_node->dev_mac, STR_MAC_SIZE);
	wds_pw_stat_arr.valid_len ++;
	if (wds_pw_stat_arr.valid_len >= WDS_PW_INFO_ARR_LEN){
		wds_pw_stat_arr.valid_len = WDS_PW_INFO_ARR_LEN - 1;
	}
}

void wds_pw_arr_del(int index){
	int i;
	wds_pw_info_t wds_pw_info_arr_tmp[WDS_PW_INFO_ARR_LEN];
	memset(wds_pw_info_arr_tmp, 0, sizeof(wds_pw_info_arr_tmp));
	memcpy(wds_pw_info_arr_tmp, &wds_pw_stat_arr.wds_pw_info_arr[index+1], (wds_pw_stat_arr.valid_len-1-index) * sizeof(wds_pw_info_t));
	memset(&wds_pw_stat_arr.wds_pw_info_arr[index], 0, (wds_pw_stat_arr.valid_len-index) * sizeof(wds_pw_info_t));
	memcpy(&wds_pw_stat_arr.wds_pw_info_arr[index], wds_pw_info_arr_tmp, (wds_pw_stat_arr.valid_len-1-index) * sizeof(wds_pw_info_t));
	wds_pw_stat_arr.valid_len--;
	wds_pw_stat_arr.wds_pw_info_arr[wds_pw_stat_arr.valid_len].wds_pwstat=1;
}

int wds_pw_arr_find_node(char *macaddr){
	int i;
	/*GPIO_DEBUG("----------start find node--[ %s ]-------", macaddr);*/
	for(i=0; i < wds_pw_stat_arr.valid_len; i++){
		//GPIO_DEBUG("cmp:[ %s ] [ %s ]", macaddr, wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
		if(!strcasecmp(wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac, macaddr)){
			GPIO_DEBUG("find success! macaddr:%s == arr.dev_mac:%s", macaddr, wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
			return i;
		}
	}
	//GPIO_DEBUG("-------not find ------");
	return -1;
}

void get_wds_pw_arr_mac(unsigned char* buf, int pw_state, char keyerr_type){
	int i = 0, first_get = 0;
	unsigned char mac_tmp[STR_MAC_SIZE+5];
	memset(mac_tmp, 0, sizeof(mac_tmp));
	if (buf == NULL){
		GPIO_ERROR("buf is null,get_wds_pw_arr_mac fail!!!");
		return;
	}
	if (pw_state == 1){
		for (i=0; i<wds_pw_stat_arr.valid_len; i++) {
			GPIO_DEBUG("get_wds_pw_arr_mac :%s", wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
			if (i==0) {
				sprintf(buf, "%s", wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
			}else{
				sprintf(mac_tmp, ", %s", wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
				strcat(buf, mac_tmp);
			}
			memset(mac_tmp, 0, sizeof(20));
		}
	}else{
		for (i=0; i<wds_pw_stat_arr.valid_len; i++) {
			if (wds_pw_stat_arr.wds_pw_info_arr[i].wds_pwstat == 0 && wds_pw_stat_arr.wds_pw_info_arr[i].keyerr_type==keyerr_type){
				if (first_get == 0){
					sprintf(buf, "%s", wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
					
				}else{
					if(KEYERR_TYPE_80211 == keyerr_type){
						sprintf(mac_tmp, ",MAC:%s", wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
					}else{
						sprintf(mac_tmp, "-%s", wds_pw_stat_arr.wds_pw_info_arr[i].dev_mac);
					}
					strcat(buf, mac_tmp);
				}
				memset(mac_tmp, 0, sizeof(mac_tmp));
				first_get ++;
			}
		}
	}
}

bool get_arr_wds_pwstat(unsigned char keyerr_type){
	int i;
	
	for (i=0; i < wds_pw_stat_arr.valid_len; i++) {
		if (wds_pw_stat_arr.wds_pw_info_arr[i].wds_pwstat == 0 && wds_pw_stat_arr.wds_pw_info_arr[i].keyerr_type==keyerr_type) {
			return false;//pw error
		}
	}

	return true;//pw right
}

void wds_pw_arr_init(void){
	int i = 0;
	wds_pw_stat_arr.valid_len = 0;
	for(i=0; i<WDS_PW_INFO_ARR_LEN; i++){
		wds_pw_stat_arr.wds_pw_info_arr[ i ].wds_pwstat = 1;
		memset(wds_pw_stat_arr.wds_pw_info_arr[ i ].dev_mac, 0, STR_MAC_SIZE);
	}
}

