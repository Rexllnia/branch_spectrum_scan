/* spctrm_scn24_wireless.h */
#ifndef _SPCTRM_SCN24_WIRELESS_H_
#define _SPCTRM_SCN24_WIRELESS_H_

#include <json-c/json.h>
#include "lib_unifyframe.h"
#include "spctrm_scn24_config.h"
#include "spctrm_scn24_dev.h"
#include "spctrm_scn24_ubus.h"
#include "libubox/avl-cmp.h"
#include "bitmap.h"

#define CHANNEL_STRING_LEN 4
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define GET_EXT_IFNAME(band) ((band) == BAND_2G)?(g_2g_ext_ifname):(((band) == BAND_5G)?g_5g_ext_ifname:NULL)

#define UNKNOW     0
#define SUPPORT_5G 1
#define SUPPORT_2G 1<<1

#define avl_find_median(avl_tree,p,node_member,counter) \
    counter = 0;\
    avl_for_each_element(avl_tree,p,node_member) \
    if ((counter)++ == (avl_tree)->count/2)


struct avl_sort_element {
	struct avl_node avl_floornoise_node;
	struct avl_node avl_obss_util_node;
	struct spctrm_scn24_channel_info spctrm_scn24_channel_info;
};

int spctrm_scn24_wireless_get_bw40_bitmap(unsigned long int* channel_bitmap,unsigned long int* bw40_channel_bitmap);
int spctrm_scn24_wireless_get_wds_state(uint8_t *mode);
int spctrm_scn24_wireless_country_channel_get_bwlist(uint8_t *bw_bitmap,uint8_t band);
int spctrm_scn24_wireless_country_channel_get_channellist(unsigned long int *channel_bitmap,uint8_t *channel_num,uint8_t bw,uint8_t band);
int spctrm_scn24_wireless_get_channel_info(struct spctrm_scn24_channel_info *info,char *ifname);
void spctrm_scn24_wireless_scan_task(struct uloop_timeout *t);
void spctrm_scn24_wireless_channel_scan(struct uloop_timeout *t);
inline int spctrm_scn24_wireless_check_channel(int channel);
inline int bitset_to_channel(int bit_set,uint8_t *channel,uint8_t band);
inline int channel_to_bitset(int channel,uint8_t *bitset,uint8_t band);
int spctrm_scn24_wireless_change_channel(int channel,uint8_t band);
int spctrm_scn24_wireless_channel_info_to_file(struct spctrm_scn24_channel_info *info,char *table_name,char *path) ;
int spctrm_scn24_wireless_channel_info_from_file(struct spctrm_scn24_channel_info *info,char *table_name,char *path);
void spctrm_scn24_wireless_change_bw(int bw,uint8_t band);
int spctrm_scn24_wireless_error_handle(struct uloop_timeout *t);
int spctrm_scn24_wireless_restore_pre_status();
int spctrm_scn24_wireless_show_channel_bitmap(unsigned long *channel_bitmap);
int spctrm_scn24_wireless_get_band_5G_apcli_ifname(char *apcli_ifname);
int spctrm_scn24_wireless_get_ext_ifname(char *ext_ifname,int band);
int spctrm_scn24_wireless_get_channel_score(struct spctrm_scn24_device_info *spctrm_scn24_device_info,
        unsigned long int* channel_bitmap,uint8_t band);


#endif

