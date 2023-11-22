/*
 * Copyright(C) 2023 Ruijie Network. All rights reserved.
 */
/*
 * rg_wds_redis.c
 * Original Author:  fuxiaofei@ruijie.com.cn, 2023-8-11
 *
 * est redis datebase about file
 *
 */
#include <hiredis/redbs.h>
#include <hiredis/redbs_common.h>
#include <hiredis/est/wds/wdsinfo.pb-c.h>
#include <hiredis/est/wds/wdstipc.pb-c.h>
#include <hiredis/est/wds/wdsrssi.pb-c.h>
#include "rg_wds.h"
#include "rg_wds_redis.h"

redbs_t *g_wds_redbs = NULL;
int g_redbs_init_enable = 0;

#define MAC_DATA(addr)   ((unsigned char*)(addr))[0], \
        ((unsigned char*)(addr))[1], \
        ((unsigned char*)(addr))[2], \
        ((unsigned char*)(addr))[3], \
        ((unsigned char*)(addr))[4], \
        ((unsigned char*)(addr))[5]
        
#define MAC_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x"  

#define IP_QUAD(addr)          \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define IP_FORMAT "%u.%u.%u.%u"

int rg_mist_mac_2_nodeadd(unsigned char *mac_src){
    unsigned int mac[6];
    unsigned int tmp;
    char buf[30];
    unsigned int zone = 1;
    unsigned int cluster = 1;
    
    memset(mac,0,sizeof(mac));
    sscanf(mac_src, "%2x:%2x:%2x:%2x:%2x:%2x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);

    /* 处理xx:xx:xx:00:0x:xx和xx:xx:xx:xx:x0:00这类mac设置tipc的node地址设置不下去的问题 */
    if((mac[3] == 0) && ((mac[4] & 0xf0) == 0)) {
        mac[3] = mac[3] + 16;
    }

    if((mac[5] == 0) && ((mac[4] & 0x0f) == 0)) {
        mac[5] = mac[5] + 2;
    }

    tmp = (mac[0] ^ mac[1] ^ mac[2]) & 0xff;
    tmp = (tmp & 0x0f) ^ (tmp >> 4);

    memset(buf,0,sizeof(buf));
    sprintf(buf,"%x%02x%02x%02x",tmp,mac[3],mac[4],mac[5]);

    tmp = 0;
    sscanf(buf,"%x",&tmp);
    /* 把rg_tipc_config脚本里面的addr="1.1"也要算上 */
	return (zone << 30) | (cluster << 28) | tmp;
}

redbs_t *get_redbs_wds_fd(void) {
    return g_wds_redbs;
}

int get_redbs_init_enable(void) {
    return g_redbs_init_enable;
}

/* wds info数据节点 dev_multi_info 数据转成数据库数据结构 */
static void redbs_wds_info2db(WWdsinfo__InfoTable *info_table,
            WWdsinfo__InfoTableKey *info_key, struct dev_multi_info *info)
{
    info_key->sn = info->sn;
    info_table->time_update = info->time_update;
    info_table->peer_sn = info->peer_sn;
    info_table->sys_mac = info->sys_mac;
    info_table->ath_mac = info->ath_mac;
    info_table->peermac = info->peermac;
    info_table->dev_type = info->dev_type;
	info_table->ipaddr = info->ipaddr;
    info_table->netmask = info->netmask;
    info_table->time = info->time;
    info_table->band = info->band;
    info_table->rssi = info->rssi;
    info_table->rssi_a = info->rssi_a;
    info_table->rate = info->rate;
    info_table->channel = info->channel;
    info_table->passwd = info->passwd;
    info_table->channf = info->channf;
    info_table->chutil = info->chutil;
    info_table->chutil_a = info->chutil_a;
    info_table->phymode = info->phymode;
	info_table->host_name = info->host_name;
    info_table->role = info->role;
    info_table->lock = info->lock;
    info_table->onlinestatus = info->onlinestatus;
    info_table->cwmp = info->cwmp;
    info_table->lan1speed = info->lan1speed;
    info_table->lan1link = info->lan1link;
    info_table->lan1duplex = info->lan1duplex;
	info_table->lan1nosupport = info->lan1nosupport;
    info_table->lan2speed = info->lan2speed;
    info_table->lan2link = info->lan2link;
    info_table->lan2duplex = info->lan2duplex;
	info_table->lan2nosupport = info->lan2nosupport;
    info_table->rx_rate = info->rx_rate;
    info_table->tx_rate = info->tx_rate;
    info_table->rx_speed = info->rx_speed;
    info_table->tx_speed = info->tx_speed;
    info_table->rx_speed_a = info->rx_speed_a;
    info_table->tx_speed_a = info->tx_speed_a;
    info_table->ssid = info->ssid;
    info_table->software_version = info->software_version;
	info_table->softver_new = info->softver_new;
	info_table->clean_sftn = info->clean_sftn;
    info_table->hardware_version = info->hardware_version;
	info_table->wds_tpye = info->wds_tpye;
    info_table->wds_distance = info->wds_distance;
    info_table->wds_txpower = info->wds_txpower;
    info_table->nf = info->nf;                    
    info_table->channel_use = info->channel_use;
    info_table->pingtime = info->pingTime;
    info_table->connecttime = info->connectTime;
    info_table->networkid = info->networkid;
    info_table->networkname = info->networkname;
	info_table->country = info->country;
    info_table->flag = info->flag;
    info_table->dfs_ch = info->dfs_ch;    
    info_table->dfs_time = info->dfs_time;  
    info_table->def_pw = info->def_pw;         
    info_table->wds_pw = info->wds_pw;        
    info_table->wdspw_state = info->wdspw_state;   
    info_table->warn_mac = info->warn_mac;     
	info_table->scan_dev_cap = info->scan_dev_cap;
	info_table->scan_pw_state = info->scan_pw_state;
    info_table->scan_warn_mac = info->scan_warn_mac;
    info_table->manage_ssid = info->manage_ssid;
    info_table->manage_bssid = info->manage_bssid;  
    info_table->dc_power = info->dc_power;
    info_table->poe_power = info->poe_power;        
    info_table->distance_max = info->distance_max;
	info_table->distance_def = info->distance_def;
	info_table->automatic_range = info->automatic_range;
	info_table->wan_speed_cap = info->wan_speed_cap;
    info_table->rssi_align = info->rssi_align;      
    return;
}

/* wds tipc node数据节点 dev_multi_info 部分数据转成数据库数据结构 */
static void redbs_wds_tipc2db(WWdstipc__TipcTable *tipc_table,
            WWdstipc__TipcTableKey *tipc_key, struct dev_multi_info *info)
{
    tipc_key->tipc_node = rg_mist_mac_2_nodeadd(info->sys_mac);
    tipc_table->sys_mac = info->sys_mac;
    tipc_table->sn = info->sn;
    tipc_table->passwd = info->passwd;
    tipc_table->networkid = info->networkid;
    return;
}

/* wds rssi info数据节点 dev_multi_info 部分数据转成数据库数据结构 */
static void redbs_wds_rssi2db(WWdsrssi__RssiTable *rssi_table,
            WWdsrssi__RssiTableKey *rssi_key, struct redis_rssi_info *rssi)
{
    rssi_key->peer_mac.len = 6;
    rssi_key->peer_mac.data = rssi->mac;
    rssi_table->uplink_rssi_h = rssi->uplink_rssi_h;
    rssi_table->uplink_rssi_v = rssi->uplink_rssi_v;
    rssi_table->downlink_rssi_h = rssi->downlink_rssi_h;
    rssi_table->downlink_rssi_v = rssi->downlink_rssi_v;
    return;
}

/* 数据库数据结构转成本地 dev_multi_info 数据结构 */
static void redbs_wds_db2info(WWdsinfo__InfoTable *info_table, struct dev_multi_info *info)
{
    strcpy(info->sn, info_table->keys->sn);
    if(info_table->time_update != NULL){info->time_update = info_table->time_update;}
    if(info_table->peer_sn != NULL){strcpy(info->peer_sn, info_table->peer_sn);}
    if(info_table->sys_mac != NULL){strcpy(info->sys_mac, info_table->sys_mac);}
    if(info_table->ath_mac != NULL){strcpy(info->ath_mac, info_table->ath_mac);}
    if(info_table->peermac != NULL){strcpy(info->peermac, info_table->peermac);}
    if(info_table->dev_type != NULL){strcpy(info->dev_type, info_table->dev_type);}
	if(info_table->ipaddr != NULL){strcpy(info->ipaddr, info_table->ipaddr);}
    if(info_table->netmask != NULL){strcpy(info->netmask, info_table->netmask);}
    if(info_table->time != NULL){strcpy(info->time, info_table->time);}
    if(info_table->band != NULL){strcpy(info->band, info_table->band);}
    if(info_table->rssi != NULL){strcpy(info->rssi, info_table->rssi);}
    if(info_table->rssi_a != NULL){strcpy(info->rssi_a, info_table->rssi_a);}
    if(info_table->rate != NULL){strcpy(info->rate, info_table->rate);}
    if(info_table->channel != NULL){strcpy(info->channel, info_table->channel);}
    if(info_table->passwd != NULL){strcpy(info->passwd, info_table->passwd);}
    if(info_table->channf != NULL){strcpy(info->channf, info_table->channf);}
    if(info_table->chutil != NULL){strcpy(info->chutil, info_table->chutil);}
    if(info_table->chutil_a != NULL){strcpy(info->chutil_a, info_table->chutil_a);}
    if(info_table->phymode != NULL){strcpy(info->phymode, info_table->phymode);}
	if(info_table->host_name != NULL){strcpy(info->host_name, info_table->host_name);}
    if(info_table->role != NULL){strcpy(info->role, info_table->role);}
    if(info_table->lock != NULL){strcpy(info->lock, info_table->lock);}
    if(info_table->onlinestatus != NULL){strcpy(info->onlinestatus, info_table->onlinestatus);}
    if(info_table->cwmp != NULL){strcpy(info->cwmp, info_table->cwmp);}
    if(info_table->lan1speed != NULL){strcpy(info->lan1speed, info_table->lan1speed);}
    if(info_table->lan1link != NULL){strcpy(info->lan1link, info_table->lan1link);}
    if(info_table->lan1duplex != NULL){strcpy(info->lan1duplex, info_table->lan1duplex);}
	if(info_table->lan1nosupport != NULL){strcpy(info->lan1nosupport, info_table->lan1nosupport);}
    if(info_table->lan2speed != NULL){strcpy(info->lan2speed, info_table->lan2speed);}
    if(info_table->lan2link != NULL){strcpy(info->lan2link, info_table->lan2link);}
    if(info_table->lan2duplex != NULL){strcpy(info->lan2duplex, info_table->lan2duplex);}
	if(info_table->lan2nosupport != NULL){strcpy(info->lan2nosupport, info_table->lan2nosupport);}
    if(info_table->rx_rate != NULL){strcpy(info->rx_rate, info_table->rx_rate);}
    if(info_table->tx_rate != NULL){strcpy(info->tx_rate, info_table->tx_rate);}
    if(info_table->rx_speed != NULL){strcpy(info->rx_speed, info_table->rx_speed);}
    if(info_table->tx_speed != NULL){strcpy(info->tx_speed, info_table->tx_speed);}
    if(info_table->rx_speed_a != NULL){strcpy(info->rx_speed_a, info_table->rx_speed_a);}
    if(info_table->tx_speed_a != NULL){strcpy(info->tx_speed_a, info_table->tx_speed_a);}
    if(info_table->ssid != NULL){strcpy(info->ssid, info_table->ssid);}
    if(info_table->software_version != NULL){strcpy(info->software_version, info_table->software_version);}
	if(info_table->softver_new != NULL){strcpy(info->softver_new, info_table->softver_new);}
	if(info_table->clean_sftn != NULL){strcpy(info->clean_sftn, info_table->clean_sftn);}
    if(info_table->hardware_version != NULL){strcpy(info->hardware_version, info_table->hardware_version);}
	if(info_table->wds_tpye != NULL){strcpy(info->wds_tpye, info_table->wds_tpye);}
    if(info_table->wds_distance != NULL){strcpy(info->wds_distance, info_table->wds_distance);}
    if(info_table->wds_txpower != NULL){strcpy(info->wds_txpower, info_table->wds_txpower);}
    if(info_table->nf != NULL){info->nf = info_table->nf;}       
    if(info_table->channel_use != NULL){info->channel_use = info_table->channel_use;}
    if(info_table->pingtime != NULL){strcpy(info->pingTime, info_table->pingtime);}
    if(info_table->connecttime != NULL){strcpy(info->connectTime, info_table->connecttime);}
    if(info_table->networkid != NULL){strcpy(info->networkid, info_table->networkid);}
    if(info_table->networkname != NULL){strcpy(info->networkname, info_table->networkname);}
	if(info_table->country != NULL){strcpy(info->country, info_table->country);}
    if(info_table->flag != NULL){info->flag = info_table->flag;}
    if(info_table->dfs_ch != NULL){info->dfs_ch = info_table->dfs_ch;}
    if(info_table->dfs_time != NULL){strcpy(info->dfs_time, info_table->dfs_time);}
    if(info_table->def_pw != NULL){strcpy(info->def_pw, info_table->def_pw);} 
    if(info_table->wds_pw != NULL){strcpy(info->wds_pw, info_table->wds_pw);}
    if(info_table->wdspw_state != NULL){strcpy(info->wdspw_state, info_table->wdspw_state);}
    if(info_table->warn_mac != NULL){strcpy(info->warn_mac, info_table->warn_mac);}
	if(info_table->scan_dev_cap != NULL){strcpy(info->scan_dev_cap, info_table->scan_dev_cap);}
	if(info_table->scan_pw_state != NULL){strcpy(info->scan_pw_state, info_table->scan_pw_state);}
    if(info_table->scan_warn_mac != NULL){strcpy(info->scan_warn_mac, info_table->scan_warn_mac);}
    if(info_table->manage_ssid != NULL){strcpy(info->manage_ssid, info_table->manage_ssid);}
    if(info_table->manage_bssid != NULL){strcpy(info->manage_bssid, info_table->manage_bssid);}
    if(info_table->dc_power != NULL){strcpy(info->dc_power, info_table->dc_power);}
    if(info_table->poe_power != NULL){strcpy(info->poe_power, info_table->poe_power);}
    if(info_table->distance_max != NULL){strcpy(info->distance_max, info_table->distance_max);}
	if(info_table->distance_def != NULL){strcpy(info->distance_def, info_table->distance_def);}
	if(info_table->automatic_range != NULL){strcpy(info->automatic_range, info_table->automatic_range);}
	if(info_table->wan_speed_cap != NULL){strcpy(info->wan_speed_cap, info_table->wan_speed_cap);}
    if(info_table->rssi_align != NULL){strcpy(info->rssi_align, info_table->rssi_align);}
    return;
}


/* 删数据库用户wds_info */
void redbs_wds_info_del_pub(unsigned char *sn)
{
    WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;

    info_key.sn = sn;
    info_table.keys = &info_key;

    if (g_redbs_init_enable == 1) {
        redbs_del(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&info_table, REDBS_BUS_JAM);    
    }
    return;     
}

/* 删数据库用户tipc_node */
void redbs_wds_tipc_del_pub(unsigned char *sys_mac)
{

    WWdstipc__TipcTable tipc_table = W_WDSTIPC__TIPC_TABLE__INIT;
    WWdstipc__TipcTableKey tipc_key = W_WDSTIPC__TIPC_TABLE_KEY__INIT;
    int tipc_node = 0;
    tipc_node = rg_mist_mac_2_nodeadd(sys_mac);
    tipc_key.tipc_node = tipc_node;
    tipc_table.keys = &tipc_key;

    if (g_redbs_init_enable == 1) {
        redbs_del(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&tipc_table, REDBS_BUS_JAM);    
    }
    return;     
}

/* 删数据库用户rssi */
void redbs_wds_rssi_del_pub(unsigned char *peer_mac)
{

    WWdsrssi__RssiTable rssi_table = W_WDSRSSI__RSSI_TABLE__INIT;
    WWdsrssi__RssiTableKey rssi_key = W_WDSRSSI__RSSI_TABLE_KEY__INIT;

    rssi_key.peer_mac.len = 6;
    rssi_key.peer_mac.data = peer_mac;
    rssi_table.keys = &rssi_key;

    if (g_redbs_init_enable == 1) {
        redbs_del(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&rssi_table, REDBS_BUS_JAM);    
    }
    return;     
}


/* 写数据库用户wds_info */
void redbs_wds_info_set_pub(struct dev_multi_info *info)
{
    WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
    info_table.keys = &info_key;

    redbs_wds_info2db(&info_table, &info_key, info);
    if (g_redbs_init_enable == 1) {
        redbs_set(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&info_table, REDBS_NON_BUS_JAM);
    }
    return;
}

/* 写数据库用户tipc */
void redbs_wds_tipc_set_pub(struct dev_multi_info *info)
{
    WWdstipc__TipcTable tipc_table = W_WDSTIPC__TIPC_TABLE__INIT;
    WWdstipc__TipcTableKey tipc_key = W_WDSTIPC__TIPC_TABLE_KEY__INIT;
    tipc_table.keys = &tipc_key;

    redbs_wds_tipc2db(&tipc_table, &tipc_key, info);
    if (g_redbs_init_enable == 1) {
        redbs_set(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&tipc_table, REDBS_NON_BUS_JAM);
    }
    return;
}

/* 写数据库用户rssi */
void redbs_wds_rssi_set_pub(struct redis_rssi_info *rssi)
{
    WWdsrssi__RssiTable rssi_table = W_WDSRSSI__RSSI_TABLE__INIT;
    WWdsrssi__RssiTableKey rssi_key = W_WDSRSSI__RSSI_TABLE_KEY__INIT;
    rssi_table.keys = &rssi_key;

    redbs_wds_rssi2db(&rssi_table, &rssi_key, rssi);
    if (g_redbs_init_enable == 1) {
        redbs_set(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&rssi_table, REDBS_NON_BUS_JAM);
    }
    return;
}

/* 写数据库用户rssi (带老化时间的接口) */
void redbs_wds_rssi_psetex_pub(struct redis_rssi_info *rssi)
{
    WWdsrssi__RssiTable rssi_table = W_WDSRSSI__RSSI_TABLE__INIT;
    WWdsrssi__RssiTableKey rssi_key = W_WDSRSSI__RSSI_TABLE_KEY__INIT;
    rssi_table.keys = &rssi_key;

    redbs_wds_rssi2db(&rssi_table, &rssi_key, rssi);
    if (g_redbs_init_enable == 1) {
        redbs_psetex(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&rssi_table, AGING_TIME, REDBS_NON_BUS_JAM);
    }
    return;
}

/* 写数据库用户wds_info (带老化时间的接口) */
void redbs_wds_info_psetex_pub(struct dev_multi_info *info)
{
    WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
    info_table.keys = &info_key;

    redbs_wds_info2db(&info_table, &info_key, info);
    if (g_redbs_init_enable == 1) {
        redbs_psetex(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&info_table, AGING_TIME, REDBS_NON_BUS_JAM);
    }
    return;
}

/* 通过SN检索数据库数据，只判断用户是否存在 */
int redbs_wds_info_get_pub_exist(unsigned char *sn)
{
    WWdsinfo__InfoTable info_table ,*p_info_table;
    info_table = (WWdsinfo__InfoTable)W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key;
    info_key = (WWdsinfo__InfoTableKey)W_WDSINFO__INFO_TABLE_KEY__INIT; 
    info_key.sn = sn;
    info_table.keys = &info_key;
    
    if (g_redbs_init_enable == 1) {
        p_info_table = (WWdsinfo__InfoTable *)redbs_get(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&info_table);
        if(!p_info_table) {
            GPIO_DEBUG("get sn fail");
            return REDBS_ERR;
        } else { 
            GPIO_DEBUG("get sn success");
            redbs_hash_res_free((redbs_obj*)p_info_table);
        }
    }
    return REDBS_OK;  
}

/* 通过SN检索数据库数据,返回完整用户数据 */
int redbs_wds_info_get_pub(unsigned char *sn, struct dev_multi_info *redis_info)
{
    WWdsinfo__InfoTable info_table ,*p_info_table;
    info_table = (WWdsinfo__InfoTable)W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key;
    info_key = (WWdsinfo__InfoTableKey)W_WDSINFO__INFO_TABLE_KEY__INIT; 
    info_key.sn = sn;
    info_table.keys = &info_key;
    if (g_redbs_init_enable == 1) {
        p_info_table = (WWdsinfo__InfoTable *)redbs_get(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&info_table);
        if(!p_info_table) {
            GPIO_DEBUG("get redis sn fail :%s", sn);
            return -1;
        } else {
            redbs_wds_db2info(p_info_table, redis_info);
            redbs_hash_res_free((redbs_obj*)p_info_table);
            #if 0
            GPIO_DEBUG("00 sn:%s",redis_info->sn);
            GPIO_DEBUG("01 time_update:%d",redis_info->time_update);
            GPIO_DEBUG("02 peer_sn:%s",redis_info->peer_sn);
            GPIO_DEBUG("03 sys_mac:%s",redis_info->sys_mac);
            GPIO_DEBUG("04 ath_mac:%s",redis_info->ath_mac);
            GPIO_DEBUG("05 peermac:%s",redis_info->peermac);
            GPIO_DEBUG("06 dev_type:%s",redis_info->dev_type);
            GPIO_DEBUG("07 ipaddr:%s",redis_info->ipaddr);
            GPIO_DEBUG("08 netmask:%s",redis_info->netmask);
            GPIO_DEBUG("09 time:%s",redis_info->time);
            GPIO_DEBUG("10 band:%s",redis_info->band);
            GPIO_DEBUG("11 rssi:%s",redis_info->rssi);
            GPIO_DEBUG("12 rssi_a:%s",redis_info->rssi_a);
            GPIO_DEBUG("13 rate:%s",redis_info->rate);
            GPIO_DEBUG("14 channel:%s",redis_info->channel);
            GPIO_DEBUG("15 passwd:%s",redis_info->passwd);
            GPIO_DEBUG("16 channf:%s",redis_info->channf);
            GPIO_DEBUG("17 chutil:%s",redis_info->chutil);
            GPIO_DEBUG("18 chutil_a:%s",redis_info->chutil_a);
            GPIO_DEBUG("19 phymode:%s",redis_info->phymode);
            GPIO_DEBUG("20 host_name:%s",redis_info->host_name);
            GPIO_DEBUG("21 role:%s",redis_info->role);
            GPIO_DEBUG("22 lock:%s",redis_info->lock);
            GPIO_DEBUG("23 onlinestatus:%s",redis_info->onlinestatus);
            GPIO_DEBUG("24 cwmp:%s",redis_info->cwmp);
            GPIO_DEBUG("25 lan1speed:%s",redis_info->lan1speed);
            GPIO_DEBUG("26 lan1link:%s",redis_info->lan1link);
            GPIO_DEBUG("27 lan1duplex:%s",redis_info->lan1duplex);
            GPIO_DEBUG("28 lan1nosupport:%s",redis_info->lan1nosupport);
            GPIO_DEBUG("29 lan2speed:%s",redis_info->lan2speed);
            GPIO_DEBUG("30 lan2link:%s",redis_info->lan2link);
            GPIO_DEBUG("31 lan2duplex:%s",redis_info->lan2duplex);
            GPIO_DEBUG("32 lan2nosupport:%s",redis_info->lan2nosupport);
            GPIO_DEBUG("33 rx_rate:%s",redis_info->rx_rate);
            GPIO_DEBUG("34 tx_rate:%s",redis_info->tx_rate);
            GPIO_DEBUG("35 rx_speed:%s",redis_info->rx_speed);
            GPIO_DEBUG("36 tx_speed:%s",redis_info->tx_speed);
            GPIO_DEBUG("37 rx_speed_a:%s",redis_info->rx_speed_a);
            GPIO_DEBUG("38 tx_speed_a:%s",redis_info->tx_speed_a);
            GPIO_DEBUG("39 ssid:%s",redis_info->ssid);
            GPIO_DEBUG("40 software_version:%s",redis_info->software_version);
            GPIO_DEBUG("41 softver_new:%s",redis_info->softver_new);
            GPIO_DEBUG("42 clean_sftn:%s",redis_info->clean_sftn);
            GPIO_DEBUG("43 hardware_version:%s",redis_info->hardware_version);
            GPIO_DEBUG("44 wds_tpye:%s",redis_info->wds_tpye);
            GPIO_DEBUG("45 wds_distance:%s",redis_info->wds_distance);
            GPIO_DEBUG("46 wds_txpower:%s",redis_info->wds_txpower);
            GPIO_DEBUG("47 nf:%d",redis_info->nf);                  
            GPIO_DEBUG("48 channel_use:%d",redis_info->channel_use);
            GPIO_DEBUG("49 pingtime:%s",redis_info->pingTime);
            GPIO_DEBUG("50 connecttime:%s",redis_info->connectTime);
            GPIO_DEBUG("51 networkid:%s",redis_info->networkid);
            GPIO_DEBUG("52 networkname:%s",redis_info->networkname);
            GPIO_DEBUG("53 country:%s",redis_info->country);
            GPIO_DEBUG("54 flag:%d",redis_info->flag);
            GPIO_DEBUG("55 dfs_ch:%d",redis_info->dfs_ch); 
            GPIO_DEBUG("56 dfs_time:%s",redis_info->dfs_time);
            GPIO_DEBUG("57 def_pw:%s",redis_info->def_pw);      
            GPIO_DEBUG("58 wds_pw:%s",redis_info->wds_pw);
            GPIO_DEBUG("59 wdspw_state:%s",redis_info->wdspw_state);
            GPIO_DEBUG("60 warn_mac:%s",redis_info->warn_mac);  
            GPIO_DEBUG("61 scan_dev_cap:%s",redis_info->scan_dev_cap);
            GPIO_DEBUG("62 scan_pw_state:%s",redis_info->scan_pw_state);
            GPIO_DEBUG("63 scan_warn_mac:%s",redis_info->scan_warn_mac);
            GPIO_DEBUG("64 manage_ssid:%s",redis_info->manage_ssid);
            GPIO_DEBUG("65 manage_bssid:%s",redis_info->manage_bssid);
            GPIO_DEBUG("66 dc_power:%s",redis_info->dc_power);
            GPIO_DEBUG("67 poe_power:%s",redis_info->poe_power);     
            GPIO_DEBUG("68 distance_max:%s",redis_info->distance_max);
            GPIO_DEBUG("69 distance_def:%s",redis_info->distance_def);
            GPIO_DEBUG("70 automatic_range:%s",redis_info->automatic_range);
            GPIO_DEBUG("71 wan_speed_cap:%s",redis_info->wan_speed_cap);  
            GPIO_DEBUG("72 rssi_align:%s",redis_info->rssi_align); 
            #endif
        }
    } else {
        return -1; 
    }
    return 0;  
}

/* 数据库订阅消息回调 */
static int redbs_wds_info_sub_cb(const redbs_t *dbs, redbs_pubsub_msg_t *msg, void *arg)
{
    WWdsinfo__InfoTable *p_info_table;
    
    int ret;
    ret = REDBS_OK;
    if (msg->error != 0) {
        return REDBS_ERR;
    }
    //GPIO_DEBUG("redis sub msg usr cmd:%d",msg->cmd);
    switch(msg->cmd) {
        case REDBS_CMD_SET:
        case REDBS_CMD_HSET:
            p_info_table = (WWdsinfo__InfoTable *)msg->value;           
            if(p_info_table) {
                GPIO_DEBUG("CMD REDBS SET TABLE INFO:%s",p_info_table->keys->sn);
                #if 0
                GPIO_DEBUG("00 sn:%s",p_info_table->keys->sn);
                GPIO_DEBUG("01 time_update:%d",p_info_table->time_update);
                GPIO_DEBUG("02 peer_sn:%s",p_info_table->peer_sn);
                GPIO_DEBUG("03 sys_mac:%s",p_info_table->sys_mac);
                GPIO_DEBUG("04 ath_mac:%s",p_info_table->ath_mac);
                GPIO_DEBUG("05 peermac:%s",p_info_table->peermac);
                GPIO_DEBUG("06 dev_type:%s",p_info_table->dev_type);
                GPIO_DEBUG("07 ipaddr:%s",p_info_table->ipaddr);
                GPIO_DEBUG("08 netmask:%s",p_info_table->netmask);
                GPIO_DEBUG("09 time:%s",p_info_table->time);
                GPIO_DEBUG("10 band:%s",p_info_table->band);
                GPIO_DEBUG("11 rssi:%s",p_info_table->rssi);
                GPIO_DEBUG("12 rssi_a:%s",p_info_table->rssi_a);
                GPIO_DEBUG("13 rate:%s",p_info_table->rate);
                GPIO_DEBUG("14 channel:%s",p_info_table->channel);
                GPIO_DEBUG("15 passwd:%s",p_info_table->passwd);
                GPIO_DEBUG("16 channf:%s",p_info_table->channf);
                GPIO_DEBUG("17 chutil:%s",p_info_table->chutil);
                GPIO_DEBUG("18 chutil_a:%s",p_info_table->chutil_a);
                GPIO_DEBUG("19 phymode:%s",p_info_table->phymode);
                GPIO_DEBUG("20 host_name:%s",p_info_table->host_name);
                GPIO_DEBUG("21 role:%s",p_info_table->role);
                GPIO_DEBUG("22 lock:%s",p_info_table->lock);
                GPIO_DEBUG("23 onlinestatus:%s",p_info_table->onlinestatus);
                GPIO_DEBUG("24 cwmp:%s",p_info_table->cwmp);
                GPIO_DEBUG("25 lan1speed:%s",p_info_table->lan1speed);
                GPIO_DEBUG("26 lan1link:%s",p_info_table->lan1link);
                GPIO_DEBUG("27 lan1duplex:%s",p_info_table->lan1duplex);
                GPIO_DEBUG("28 lan1nosupport:%s",p_info_table->lan1nosupport);
                GPIO_DEBUG("29 lan2speed:%s",p_info_table->lan2speed);
                GPIO_DEBUG("30 lan2link:%s",p_info_table->lan2link);
                GPIO_DEBUG("31 lan2duplex:%s",p_info_table->lan2duplex);
                GPIO_DEBUG("32 lan2nosupport:%s",p_info_table->lan2nosupport);
                GPIO_DEBUG("33 rx_rate:%s",p_info_table->rx_rate);
                GPIO_DEBUG("34 tx_rate:%s",p_info_table->tx_rate);
                GPIO_DEBUG("35 rx_speed:%s",p_info_table->rx_speed);
                GPIO_DEBUG("36 tx_speed:%s",p_info_table->tx_speed);
                GPIO_DEBUG("37 rx_speed_a:%s",p_info_table->rx_speed_a);
                GPIO_DEBUG("38 tx_speed_a:%s",p_info_table->tx_speed_a);
                GPIO_DEBUG("39 ssid:%s",p_info_table->ssid);
                GPIO_DEBUG("40 software_version:%s",p_info_table->software_version);
                GPIO_DEBUG("41 softver_new:%s",p_info_table->softver_new);
                GPIO_DEBUG("42 clean_sftn:%s",p_info_table->clean_sftn);
                GPIO_DEBUG("43 hardware_version:%s",p_info_table->hardware_version);
                GPIO_DEBUG("44 wds_tpye:%s",p_info_table->wds_tpye);
                GPIO_DEBUG("45 wds_distance:%s",p_info_table->wds_distance);
                GPIO_DEBUG("46 wds_txpower:%s",p_info_table->wds_txpower);
                GPIO_DEBUG("47 nf:%d",p_info_table->nf);                  
                GPIO_DEBUG("48 channel_use:%d",p_info_table->channel_use);
                GPIO_DEBUG("49 pingtime:%s",p_info_table->pingtime);
                GPIO_DEBUG("50 connecttime:%s",p_info_table->connecttime);
                GPIO_DEBUG("51 networkid:%s",p_info_table->networkid);
                GPIO_DEBUG("52 networkname:%s",p_info_table->networkname);
                GPIO_DEBUG("53 country:%s",p_info_table->country);
                GPIO_DEBUG("54 flag:%d",p_info_table->flag);
                GPIO_DEBUG("55 dfs_ch:%d",p_info_table->dfs_ch); 
                GPIO_DEBUG("56 dfs_time:%s",p_info_table->dfs_time);
                GPIO_DEBUG("57 def_pw:%s",p_info_table->def_pw);      
                GPIO_DEBUG("58 wds_pw:%s",p_info_table->wds_pw);
                GPIO_DEBUG("59 wdspw_state:%s",p_info_table->wdspw_state);
                GPIO_DEBUG("60 warn_mac:%s",p_info_table->warn_mac);  
                GPIO_DEBUG("61 scan_dev_cap:%s",p_info_table->scan_dev_cap);
                GPIO_DEBUG("62 scan_pw_state:%s",p_info_table->scan_pw_state);
                GPIO_DEBUG("63 scan_warn_mac:%s",p_info_table->scan_warn_mac);
                GPIO_DEBUG("64 manage_ssid:%s",p_info_table->manage_ssid);
                GPIO_DEBUG("65 manage_bssid:%s",p_info_table->manage_bssid);
                GPIO_DEBUG("66 dc_power:%s",p_info_table->dc_power);
                GPIO_DEBUG("67 poe_power:%s",p_info_table->poe_power);     
                GPIO_DEBUG("68 distance_max:%s",p_info_table->distance_max);
                GPIO_DEBUG("69 distance_def:%s",p_info_table->distance_def);
                GPIO_DEBUG("70 automatic_range:%s",p_info_table->automatic_range);
                GPIO_DEBUG("71 wan_speed_cap:%s",p_info_table->wan_speed_cap);   
                GPIO_DEBUG("72 rssi_align:%s",p_info_table->rssi_align); 
                #endif
            }
            break;

        case REDBS_CMD_DEL:
        case REDBS_CMD_HDEL: 
            GPIO_DEBUG("CMD REDBS DEL: delete wds info by kick");
            break;
        case REDBS_CMD_EXPIRE:
            GPIO_DEBUG("CMD REDBS SET: set wds info expire time");
            break;
        case REDBS_CMD_EXPIRED:
            GPIO_DEBUG("CMD REDBS DEL: delete wds info by timeout");
            p_info_table = (WWdsinfo__InfoTable *)msg->value;           
            if(p_info_table) {
                GPIO_DEBUG("delete wds info sn:%s",p_info_table->keys->sn);
            }
            break;

        default:
            GPIO_ERROR("unknow cmd:%d",msg->cmd);
    }
    return 0;
}


/* 数据库订阅消息回调tipc node */
static int redbs_wds_tipc_sub_cb(const redbs_t *dbs, redbs_pubsub_msg_t *msg, void *arg)
{
    WWdstipc__TipcTable *p_tipc_table;
    
    int ret;
    ret = REDBS_OK;
    if (msg->error != 0) {
        return REDBS_ERR;
    }
    //GPIO_DEBUG("redis sub msg usr cmd:%d",msg->cmd);
    switch(msg->cmd) {
        case REDBS_CMD_SET:
        case REDBS_CMD_HSET:
            p_tipc_table = (WWdstipc__TipcTable *)msg->value;           
            if(p_tipc_table) {
                GPIO_DEBUG("CMD REDBS SET TABLE NODE:%d",p_tipc_table->keys->tipc_node);
            }
            break;

        case REDBS_CMD_DEL:
        case REDBS_CMD_HDEL: 
            GPIO_DEBUG("CMD REDBS DEL: delete tipc node by kick");
            break;
        case REDBS_CMD_EXPIRE:
            GPIO_DEBUG("CMD REDBS SET: set tipc node expire time");
            break;
        case REDBS_CMD_EXPIRED:
            GPIO_DEBUG("CMD REDBS DEL: delete tipc node by timeout");
            p_tipc_table = (WWdstipc__TipcTable *)msg->value;           
            if(p_tipc_table) {
                GPIO_DEBUG("delete tipc node:%d",p_tipc_table->keys->tipc_node);
            }
            break;

        default:
            GPIO_ERROR("unknow cmd:%d",msg->cmd);
    }
    return 0;
}


/* 数据库订阅消息回调rssi info */
static int redbs_wds_rssi_sub_cb(const redbs_t *dbs, redbs_pubsub_msg_t *msg, void *arg)
{
    WWdsrssi__RssiTable *p_rssi_table;
    
    int ret;
    ret = REDBS_OK;
    if (msg->error != 0) {
        return REDBS_ERR;
    }
    //GPIO_DEBUG("redis sub msg usr cmd:%d",msg->cmd);
    switch(msg->cmd) {
        case REDBS_CMD_SET:
        case REDBS_CMD_HSET:
            p_rssi_table = (WWdsrssi__RssiTable *)msg->value;           
            if(p_rssi_table) {
                  GPIO_DEBUG("CMD REDBS SET TABLE RSSI:"MAC_FORMAT,MAC_DATA(p_rssi_table->keys->peer_mac.data));
            //    GPIO_DEBUG("01 uplink_rssi_h:%d",p_rssi_table->uplink_rssi_h);
            //    GPIO_DEBUG("02 uplink_rssi_v:%d",p_rssi_table->uplink_rssi_v);
            //    GPIO_DEBUG("03 downlink_rssi_h:%d",p_rssi_table->downlink_rssi_h);
            //    GPIO_DEBUG("04 downlink_rssi_v:%d",p_rssi_table->downlink_rssi_v);
            }
            break;

        case REDBS_CMD_DEL:
        case REDBS_CMD_HDEL: 
            GPIO_DEBUG("CMD REDBS DEL: delete rssi by kick");
            break;
        case REDBS_CMD_EXPIRE:
            //GPIO_DEBUG("CMD REDBS SET: set rssi expire time");
            break;
        case REDBS_CMD_EXPIRED:
            GPIO_DEBUG("CMD REDBS DEL: delete rssi by timeout");
            p_rssi_table = (WWdsrssi__RssiTable *)msg->value;           
            if(p_rssi_table) {
                GPIO_DEBUG("delete rssi info:"MAC_FORMAT,MAC_DATA(p_rssi_table->keys->peer_mac.data));
            }
            break;

        default:
            GPIO_ERROR("unknow cmd:%d",msg->cmd);
    }
    return 0;
}


static int redbs_wds_connected_cb(const redbs_t *dbs, redbs_db_type_t db,
            redbs_conn_type_t opt, void *argv)
{
    int ret;
    /* wds info all */
    WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
    WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
    info_table.keys = &info_key;

    /* tipc node info */
    WWdstipc__TipcTable tipc_table = W_WDSTIPC__TIPC_TABLE__INIT;
    WWdstipc__TipcTableKey tipc_key = W_WDSTIPC__TIPC_TABLE_KEY__INIT;
    tipc_table.keys = &tipc_key;

    /* rssi info */
    WWdsrssi__RssiTable rssi_table = W_WDSRSSI__RSSI_TABLE__INIT;
    WWdsrssi__RssiTableKey rssi_key = W_WDSRSSI__RSSI_TABLE_KEY__INIT;
    rssi_table.keys = &rssi_key;
    
    /* TODO:订阅数据库wds_info_all消息 */
    ret = redbs_subscribe(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&info_table, 0,
            redbs_wds_info_sub_cb, NULL);
    if (ret != REDBS_OK) {
        GPIO_ERROR("wds list info candidate subscribe redis failed!, ret: %d", ret);
        return REDBS_ERR;
    }

    /* TODO:订阅数据库tipc_node消息 */
    ret = redbs_subscribe(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&tipc_table, 0,
            redbs_wds_tipc_sub_cb, NULL);
    if (ret != REDBS_OK) {
        GPIO_ERROR("wds tipc node info candidate subscribe redis failed!, ret: %d", ret);
        return REDBS_ERR;
    }

    /* TODO:订阅数据库rssi消息 */
    ret = redbs_subscribe(g_wds_redbs, REDBS_HOST_DB, (const redbs_obj *)&rssi_table, 0,
            redbs_wds_rssi_sub_cb, NULL);
    if (ret != REDBS_OK) {
        GPIO_ERROR("wds rssi info candidate subscribe redis failed!, ret: %d", ret);
        return REDBS_ERR;
    }
    g_redbs_init_enable = 1;
    return ret;
}

static int redbs_wds_reconnected_cb(const redbs_t *dbs, redbs_db_type_t db,
            redbs_reconnect_type_t op, void *argv)
{
    int ret;

    ret = redbs_wds_connected_cb(dbs, db, op, argv);
    GPIO_ERROR("redis reconnected...");

    return ret;
}

static int redbs_wds_disconnected_cb(const redbs_t *dbs, redbs_db_type_t db,
            redbs_conn_type_t opt, void *argv)
{
    g_redbs_init_enable = 0;
    GPIO_ERROR("redis disconnect...");
    return 0;
}

/* 数据库初始化 */
int rg_wds_redis_init(void)
{
    int ret;
    void *agr = NULL;
    g_wds_redbs = redbs_init("RG_WDS_REDBS", NULL);
    if (g_wds_redbs == NULL) {
        GPIO_ERROR("Init failed. Reason: [rg wds redis init fail]");
        return -1;
    }
   
    g_redbs_init_enable = 0;
    for (;;) {
        GPIO_ERROR("redis connect loop !");
        ret = redbs_connect(g_wds_redbs, REDBS_HOST_DB, (redbs_connect_cb *)redbs_wds_connected_cb, agr);
        if (ret == REDBS_OK) {
            GPIO_ERROR("redbs_connect REDBS_HOST_DB successed!");
            break;
        }
        sleep(REDIS_RETRY_SLEEP_INTERVAL);
    }
    if (ret != REDBS_OK) {
        GPIO_ERROR("redis connect failed!");
        redbs_finish(g_wds_redbs);
        return -1;
    }
    redbs_set_reconnect_cb(g_wds_redbs, REDBS_HOST_DB, (redbs_reconnect_cb *)redbs_wds_reconnected_cb, agr);
    redbs_set_disconnect_cb(g_wds_redbs, REDBS_HOST_DB, (redbs_disconnect_cb *)redbs_wds_disconnected_cb, agr);

    g_redbs_init_enable = 1;
    GPIO_DEBUG("redis init success");
    redbs_run(g_wds_redbs);
    redbs_finish(g_wds_redbs);
    return 0;
}

/* 数据库线程初始化 */
int rg_wds_redis_sub_thread()
{
    int ret;
    /* set thread name */
    //prctl(PR_SET_NAME, "wds_redis_sub");
begin:
    ret = rg_wds_redis_init();
    GPIO_ERROR("rg_wds_redis_sub_thread");
    if (ret == -1) {
        GPIO_ERROR("rg_wds_redis_init fail");
        sleep(1);
        goto begin;
    }
    return;
}

