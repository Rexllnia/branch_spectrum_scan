
/*
 * Copyright(C) 2023 Ruijie Network. All rights reserved.
 */
/*
 * rg_tipc_redis.c
 * Original Author:  fuxiaofei@ruijie.com.cn, 2023-8-23
 *
 * est tipc redis datebase about file
 *
 */
#include <hiredis/redbs.h>
#include <hiredis/redbs_common.h>
#include <hiredis/est/wds/wdstipc.pb-c.h>
#include "rg_tipc_redis.h"

redbs_t *g_tipc_redbs = NULL;
int g_redbs_init_enable = 0;

static void redbs_db2tipc(WWdstipc__TipcTable *tipc_table, struct tipc_redis_info *info)
{
    info->tipc_node = tipc_table->keys->tipc_node;
    if(tipc_table->sn != NULL)       {strcpy(info->sn, tipc_table->sn);}
    if(tipc_table->sys_mac != NULL)  {strcpy(info->sys_mac, tipc_table->sys_mac);}
    if(tipc_table->networkid != NULL){strcpy(info->networkid, tipc_table->networkid);}
    if(tipc_table->passwd != NULL)   {strcpy(info->passwd, tipc_table->passwd);}
    return;
}

int redbs_tipc_get_pub(unsigned int node, struct tipc_redis_info *tipc_info)
{
    WWdstipc__TipcTable tipc_table ,*p_tipc_table;
    tipc_table = (WWdstipc__TipcTable)W_WDSTIPC__TIPC_TABLE__INIT;
    WWdstipc__TipcTableKey tipc_key;
    tipc_key = (WWdstipc__TipcTableKey)W_WDSTIPC__TIPC_TABLE_KEY__INIT;

    tipc_key.tipc_node = node;
    tipc_table.keys = &tipc_key;
    
    if (g_redbs_init_enable == 1) {
        p_tipc_table = (WWdstipc__TipcTable *)redbs_get(g_tipc_redbs, REDBS_HOST_DB, (const redbs_obj *)&tipc_table);
        if(!p_tipc_table) {
            return -1;
        } else {
            redbs_db2tipc(p_tipc_table, tipc_info);
            redbs_hash_res_free((redbs_obj*)p_tipc_table);
        }
    } else {
        return -1; 
    }
    return 0;  
}

static int redbs_tipc_connected_cb(const redbs_t *dbs, redbs_db_type_t db,
            redbs_conn_type_t opt, void *argv)
{
    g_redbs_init_enable = 1;
    //printf("redis connected...\n");
    return REDBS_OK;
}

static int redbs_tipc_reconnected_cb(const redbs_t *dbs, redbs_db_type_t db,
            redbs_reconnect_type_t op, void *argv)
{
    int ret;
    ret = redbs_tipc_connected_cb(dbs, db, op, argv);
    return ret;
}

static int redbs_tipc_disconnected_cb(const redbs_t *dbs, redbs_db_type_t db,
            redbs_conn_type_t opt, void *argv)
{
    g_redbs_init_enable = 0;
    //printf("redis disconnect...\n");
    return 0;
}

int rg_tipc_redis_init(void)
{
    int ret;
    void *agr = NULL;
    g_tipc_redbs = redbs_init("RG_TIPC_REDBS", NULL);
    if (g_tipc_redbs == NULL) {
        printf("Init failed. Reason: [rg tipc redis init fail]\n");
        return -1;
    }
   
    g_redbs_init_enable = 0;
    for (;;) {
        ret = redbs_connect(g_tipc_redbs, REDBS_HOST_DB, (redbs_connect_cb *)redbs_tipc_connected_cb, agr);
        if (ret == REDBS_OK) {
            break;
        }
        sleep(5);
    }
    if (ret != REDBS_OK) {
        //printf("redis connect failed!\n");
        redbs_finish(g_tipc_redbs);
        return -1;
    }
    redbs_set_reconnect_cb(g_tipc_redbs, REDBS_HOST_DB, (redbs_reconnect_cb *)redbs_tipc_reconnected_cb, agr);
    redbs_set_disconnect_cb(g_tipc_redbs, REDBS_HOST_DB, (redbs_disconnect_cb *)redbs_tipc_disconnected_cb, agr);

    g_redbs_init_enable = 1;
    redbs_run(g_tipc_redbs);
    redbs_finish(g_tipc_redbs);
    return 0;
}

int rg_tipc_redis_thread(void)
{
    int ret;
begin:
    ret = rg_tipc_redis_init();
    if (ret == -1) {
        printf("rg_tipc_redis_init fail\n");
        sleep(5);
        goto begin;
    }
    return;
}

