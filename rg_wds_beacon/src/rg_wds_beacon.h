/*
 * Copyright(C) 2013 Ruijie Network. All rights reserved.
 */
/*
 * rj_wds_basic.h
 * Original Author: zhangyongzhen@ruijie.com.cn 2018-04-14
 *
 * wds
 *
 */

#ifndef _RJ_WDS_BEACON_H_
#define _RJ_WDS_BEACON_H_

#define WDS_NTV_SN 					14
#define MAC_ADDR_LEN 				6
#define DEV_TYPE_LEN                16
#define DEV_NAME_LEN                65 
#define PRJ_NAME_LEN                65
#define MAX_LEN_OF_SSID             32
#define LEN_PSK                     64

#define KEYERR_TYPE_80211              0
#define KEYERR_TYPE_CUSTOM             1

unsigned char g_wdsbcn_ntvsn[WDS_NTV_SN];

extern void rj_wdsssid_cp_ntvsn(unsigned char *ntv_sn);
struct expand_wds_beacon_info_s{
	char dev_type[DEV_TYPE_LEN];
	char dev_mac[MAC_ADDR_LEN];
	char ath_mac[MAC_ADDR_LEN];
	char dev_name[DEV_NAME_LEN];
	char prj_name[PRJ_NAME_LEN];
	char dev_nm_stat;
	char prj_nm_stat;
	char pw_stat;
	
};
struct send_to_app_scaninfo{
	unsigned char *ssid;
	unsigned char wds_status;
	unsigned char role;
	unsigned int rssi;
	unsigned char *mac;
	unsigned char *sn;
//The following are the new parameters
	unsigned char is_exist_expend;
	unsigned char *dev_type;
	unsigned char *dev_mac;
	unsigned char *ath_mac;
	unsigned char *dev_name;
	unsigned char *prj_name;
	unsigned char dev_nm_stat;
	unsigned char prj_nm_stat;
	unsigned char pw_stat;
};

#endif /* _RJ_WDS_BEACON_H_ */