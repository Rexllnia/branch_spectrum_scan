#include "rg_wds.h"

void rg_wds_fill_head(struct wds_date_head *data,char flag,char len) {
	memset(data,0,sizeof(struct wds_date_head));
	data->role = rg_ath_info_t.role;
	data->lock = rg_gpio_info_t.gpio_lock_value;
	data->unuse = 0x55;
	data->unuse2 = 0xaa;
	memcpy(data->name,"abcd",strlen("abcd"));	
	data->sync_flag = flag;
    data->cpe_num = len;
}
