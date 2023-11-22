
/*
 * Copyright(C) 2023 Ruijie Network. All rights reserved.
 */
/*
 * rg_tipc_redis.h
 * Original Author:  fuxiaofei@ruijie.com.cn, 2023-8-23
 *
 * est tipc redis datebase about file
 *
 */
 
#define EWEB_DEF_PW     "admin"
#define DEF_NETWORKID   "0"

struct tipc_redis_info {
    unsigned int tipc_node;
    unsigned char sn[30];
    unsigned char sys_mac[20];
    char networkid[33];
    unsigned char passwd[100];
};

int redbs_tipc_get_pub(unsigned int node, struct tipc_redis_info *redis_info);
int rg_tipc_redis_thread(void);

