#include "rg_tipc.h"
#include<sys/resource.h>
int g_tipc_upgrd_cnt = 0;
int LOCAL_UPGD_FLAG = 0;
bool g_tipc_cond_flag = false;
tipc_upgrade_node_t tipc_un = {0};
struct list_head *g_tipc_upgrade_list = (struct list_head *)&tipc_un;
pthread_mutex_t mtx_tipc_upgrd_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mtx_tipc_cond_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t tipc_cond    = PTHREAD_COND_INITIALIZER;
pthread_mutex_t collect_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  collect_cond = PTHREAD_COND_INITIALIZER;


int tipc_cmd_check_symbol(char *buf)
{
    if (buf == NULL) { 
//		TIPC_DEBUG("buf is null no check return sucess");
        return SUCESS;
    }
	if ((strstr(buf,"&")==NULL) && (strstr(buf,"|")==NULL) && (strstr(buf,";")==NULL) && (strstr(buf,"`")==NULL)) {
	    return SUCESS;
	} else {
		return FAIL;
	}
}

const char * ether_sprintf(const unsigned char mac[6])
{
    static char buf[32];

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

int rg_tipc_del_all_node_func(void)
{
    struct list_head *pos, *n;
    tipc_upgrade_node_t *tmp;


    tmp = NULL;
    pthread_mutex_lock(&mtx_tipc_upgrd_lock);
    list_for_each_safe(pos, n, g_tipc_upgrade_list) {
        if (pos) {
            TIPC_DEBUG("tipc del member[%s].", ((tipc_upgrade_node_t *)pos)->peersn);
            tmp = (tipc_upgrade_node_t *)pos;
            list_del(pos);
            free(tmp);
            tmp = NULL;
        }
    }
    pthread_mutex_unlock(&mtx_tipc_upgrd_lock);

    return SUCESS;
}

void rg_tipc_client_upgrade_func(unsigned char *trans_sn,
                                            unsigned char *peer_sn,
                                            unsigned char *upgrade_cmd)
{
    unsigned char native_sn[20], mac[20];
    unsigned int instance;
    unsigned char buf[BUF_SIZE];
    struct sockaddr_tipc server_addr;
    struct timeval timeout={5, 0};
    int sd;

    if (!trans_sn) {
        TIPC_DEBUG("trans_sn is NULL!");
        return;
    }

    if (!peer_sn) {
        TIPC_DEBUG("peer_sn is NULL!");
        return;
    }

    if (!upgrade_cmd) {
        TIPC_DEBUG("upgrade_cmd is NULL!");
        return;
    }

    if (strcmp(upgrade_cmd, UPGRADE_REQ_CMD) != 0 &&
        strcmp(upgrade_cmd, UPGRADE_HS2_CMD) != 0 &&
        strcmp(upgrade_cmd, UPGRADE_HS3_CMD) != 0 &&
        strcmp(upgrade_cmd, UPGRADE_HS4_CMD) != 0) {
        TIPC_DEBUG("UPGRADE CMD ERR.");
        return;
    }

    /* Get native serial number */
    memset(native_sn, 0, sizeof(native_sn));
    rg_misc_read_file("/proc/rg_sys/serial_num", native_sn, sizeof(native_sn) - 1);

    if (strlen(peer_sn) != 17 && !strchr(peer_sn, ':')) {
        memset(mac,0,sizeof(mac));
        char num = 0;
        while(1){
            rg_sn_to_mac(peer_sn, mac);
            if (num++ > 3 || strlen(mac) == 17) {
                break;
            }
        }
        if (strlen(mac) != 17) {
            printf("error\n");
            return;
        }
        instance = rg_mist_mac_2_nodeadd(mac);
    } else {
        instance = rg_mist_mac_2_nodeadd(peer_sn);
    }

    if (instance == 0) {
        TIPC_DEBUG("error");
        goto end;
    }

    memset(buf,0,sizeof(buf));
    snprintf(buf, BUF_SIZE, "%s#%s#%s", upgrade_cmd, trans_sn, native_sn);
    strncpy(buf, upgrade_cmd, strlen(upgrade_cmd));
//    TIPC_DEBUG("buf:%s", buf);

    if (wait_for_server(SERVER_TYPE_UPGRADE, instance, 3000) == FAIL){
        TIPC_DEBUG("error");
        goto end;
    }

    sd = socket(AF_TIPC, SOCK_RDM, 0);

    server_addr.family                  = AF_TIPC;
    server_addr.addrtype                = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type     = SERVER_TYPE_UPGRADE;
    server_addr.addr.name.name.instance = instance;
    server_addr.addr.name.domain        = 0;

    setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(struct timeval));
    if (0 > sendto(sd, buf, strlen(buf) + 1,0,(struct sockaddr*)&server_addr, sizeof(server_addr))) {
        TIPC_DEBUG("error");
        goto end;
    }
end:
    if (sd >= 0) {
        close(sd);
    }

    return;
}

int rg_tipc_client_socket_link(struct list_head *pos,
                                         unsigned char *upgrade_cmd,
                                         unsigned char *native_sn,
                                         unsigned char *version_name)
{
    int sd, ret;
    unsigned int instance = 0;
    unsigned char buf[BUF_SIZE];
    unsigned char mac[20];
    unsigned char *sn;
    struct sockaddr_tipc server_addr;
    struct timeval timeout={2, 0};
    tipc_upgrade_node_t *tipc_un = (tipc_upgrade_node_t *)pos;

    /* Convert serial number to macaddr */
    sn = tipc_un->peersn;
    if (strlen(sn) != 17 && !strchr(sn, ':')) {
        memset(mac, 0, sizeof(mac));
        char num = 0;
        while (1) {
            rg_sn_to_mac(sn, mac);
            if (num++ > 3 || strlen(mac) == 17) {
                break;
            }
        }
        if (strlen(mac) != 17) {
            TIPC_DEBUG("error");
            ret = FAIL;
            goto end;
        }
        instance = rg_mist_mac_2_nodeadd(mac);
    } else {
        instance = rg_mist_mac_2_nodeadd(sn);
    }

    if (instance == 0) {
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    memset(buf, 0, sizeof(buf));
    snprintf(buf, BUF_SIZE, "%s#%s#%s#%s", upgrade_cmd, sn, native_sn, version_name);
//    TIPC_DEBUG("buf:%s", buf);

    if (wait_for_server(SERVER_TYPE_UPGRADE, instance, 3000) == FAIL){
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    sd = socket(AF_TIPC, SOCK_RDM, 0);

    server_addr.family                  = AF_TIPC;
    server_addr.addrtype                = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type     = SERVER_TYPE_UPGRADE;
    server_addr.addr.name.name.instance = instance;
    server_addr.addr.name.domain        = 0;
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
    if (0 > sendto(sd, buf, strlen(buf) + 1, 0, (struct sockaddr*)&server_addr, sizeof(server_addr))) {
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval));
    memset(buf, 0, sizeof(buf));
    if (0 >= recv(sd, buf, sizeof(buf) - 1, 0)) {
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    ret = SUCESS;
end:
    if (sd) {
        close(sd);
    }

    return ret;
}

tipc_upgrade_node_t *rg_tipc_find_and_update_func(tipc_upgrade_node_t *tipc_un)
{
    struct list_head *pos;
    tipc_upgrade_node_t *tmp;

    if (!tipc_un) {
        TIPC_DEBUG("tipc upgrade node is NULL!");
        return NULL;
    }

    tmp = NULL;
    list_for_each(pos, g_tipc_upgrade_list) {
        if (pos && !strcmp(((tipc_upgrade_node_t *)pos)->peersn, tipc_un->peersn)) {
            TIPC_DEBUG("Tipc find member[%s].", tipc_un->peersn);
            tmp = (tipc_upgrade_node_t *)pos;
            break;
        }
    }

    return tmp;
}

int rg_tipc_add_list_func(tipc_upgrade_node_t *tipc_un)
{
    struct list_head *pos;
    tipc_upgrade_node_t *tmp;

    if (!tipc_un) {
        TIPC_DEBUG("tipc upgrade node is NULL!");
        return FAIL;
    }

    pthread_mutex_lock(&mtx_tipc_upgrd_lock);
    tmp = rg_tipc_find_and_update_func(tipc_un);
    if (!tmp) {
        tmp = (tipc_upgrade_node_t *)rg_tipc_malloc(sizeof(tipc_upgrade_node_t));
        if (!tmp) {
            TIPC_DEBUG("tipc upgrade-node malloc err.");
            pthread_mutex_unlock(&mtx_tipc_upgrd_lock);
            return FAIL;
        }
        memset(tmp->peersn, 0, sizeof(tmp->peersn));
        strncpy(tmp->peersn, tipc_un->peersn, strlen(tipc_un->peersn));
        tmp->flag = tipc_un->flag;
        (void)list_add_tail(&tmp->list, g_tipc_upgrade_list);
    }
    pthread_mutex_unlock(&mtx_tipc_upgrd_lock);

    return SUCESS;
}

void rg_tipc_thr_hndshk(unsigned char *upgrd_cmd,        unsigned char *ntv_sn)
{
    struct list_head *pos;
    int flag = 0;

    if (!upgrd_cmd) {
        TIPC_DEBUG("upgrd cmd is NULL!");
        return;
    }

    if (!ntv_sn) {
        TIPC_DEBUG("native sn is NULL!");
        return;
    }

    pthread_mutex_lock(&mtx_tipc_upgrd_lock);
    list_for_each(pos, g_tipc_upgrade_list) {
        if (pos
            && ((tipc_upgrade_node_t *)pos)->flag == false
            && ((tipc_upgrade_node_t *)pos)->hs2_flag == true) {
            /* recv 2/4 handshake pkt flag, and then send 3/4 handshake pkt */
            TIPC_DEBUG("three handshake[%s]", ((tipc_upgrade_node_t *)pos)->peersn);
            (void)rg_tipc_client_upgrade_func(ntv_sn, ((tipc_upgrade_node_t *)pos)->peersn, upgrd_cmd);
        }
    }
    pthread_mutex_unlock(&mtx_tipc_upgrd_lock);
}

int rg_tipc_create_dl_dir(void)
{
    if (access(TIPC_DOWNLOAD_DIR, NULL) != 0) {
        if (mkdir(TIPC_DOWNLOAD_DIR, 0755) == -1) {
            TIPC_DEBUG("mkdir error[%s]", TIPC_DOWNLOAD_DIR);
            return FAIL;
        }
    }

    return SUCESS;
}

int rg_tipc_mv_upgrd_file(unsigned char *version_name)
{
    int ret;
    unsigned char version_dir[128], new_path[128];
    if (!version_name) {
        TIPC_DEBUG("version_name is NULL!");
        ret = FAIL;
        goto end;
    }

    memset(version_dir, 0, sizeof(version_dir));
    snprintf(version_dir, sizeof(version_dir), "/tmp/%s", version_name);

    if (access(version_dir, F_OK) != 0) {
        TIPC_DEBUG("upgrade file no exist!");
        ret = FAIL;
        goto end;
    }

    ret = rg_tipc_create_dl_dir();
    if (ret == FAIL) {
        TIPC_DEBUG("create download dir is error.");
        goto end;
    }

    memset(new_path, 0, sizeof(new_path));
    snprintf(new_path, sizeof(new_path), "%s%s", TIPC_DOWNLOAD_DIR, version_name);
    if (rename(version_dir, new_path) == FAIL) {
        ret = FAIL;
        goto end;
    }
    ret = SUCESS;

end:

    return ret;
}

int rg_tipc_local_upgrd_prepare(unsigned char *version_name)
{
    unsigned char rmt_type[64], rmt_ver_num[12], native_type[16], ntv_ver[48];
    unsigned char *ntv_ver_num, *version;
    int ret;
	

    if (!version_name) {
        TIPC_DEBUG("version_name is NULL.");
        ret = FAIL;
        goto end;
    }

    memset(native_type, 0, sizeof(native_type));
    rg_misc_read_file("/proc/rg_sys/product_class", native_type, sizeof(native_type) - 1);
    memset(ntv_ver, 0, sizeof(ntv_ver));
    rg_misc_read_file("/proc/rg_sys/software_version", ntv_ver, sizeof(ntv_ver) - 1);
    ntv_ver_num = rg_filter_ver_to_int(ntv_ver);
    if (!ntv_ver_num) {
        TIPC_DEBUG("convert version to num fail!");
        ret = FAIL;
        goto end;
    }

    version = rg_tipc_execute_buf(TIPC_LOCAL_TAR_SOFTVER, version_name);
    if (!version) {
        TIPC_DEBUG("Execute cmd[%s] error!", TIPC_LOCAL_TAR_SOFTVER);
        ret = FAIL;
        goto end;
    }
//    TIPC_DEBUG("version %s", version);

    memset(rmt_type, 0, sizeof(rmt_type));
    memset(rmt_ver_num, 0, sizeof(rmt_ver_num));
    ret = rg_filter_softversion_devtype(version, rmt_type, rmt_ver_num);
    if (ret == FAIL) {
        TIPC_DEBUG("version unmatch!!!");
        ret = FAIL;
        goto end;
    }
	if (rg_misc_popen(TIPC_GET_SOFTVER_FROM_PID, rmt_type, sizeof(rmt_type)) == -1) {
		TIPC_DEBUG("TIPC_GET_SOFTVER_FROM_PID err!!!");
        ret = FAIL;
        goto end;	
	}
	TIPC_DEBUG("native_type:%s rmt_type:%s", native_type, rmt_type);
    if (strstr(rmt_type,native_type) == NULL) {
        TIPC_DEBUG("devtype unmatch!!!");
        ret = FAIL;
        goto end;
    }

    if (rg_version_sync_check(rmt_ver_num, ntv_ver_num) == false) {
        TIPC_DEBUG("ver_num unmatch!!!");
        ret = FAIL;
        goto end;
    }

    ret = SUCESS;
end:
    if (version) {
        free(version);
        version = NULL;
    }

    return ret;
}

int rg_tipc_thr_hndshk_and_upgrd(unsigned char *upgrd_cmd,
                                            unsigned char *ntv_sn,
                                            unsigned char *version)
{
    struct list_head *pos;
    int ret, flag;
    unsigned char sysupgrade_cmd[128];

    if (!upgrd_cmd) {
        TIPC_DEBUG("upgrd cmd is NULL!");
        return FAIL;
    }

    if (!ntv_sn) {
        TIPC_DEBUG("native sn is NULL!");
        return FAIL;
    }

    if (!version) {
        TIPC_DEBUG("version is NULL!");
        return FAIL;
    }

    while (1) {
        sleep(2);
        flag = 0;
        list_for_each(pos, g_tipc_upgrade_list) {
            if (pos && ((tipc_upgrade_node_t *)pos)->flag == true) {
                flag = 1;
            }
        }

        if (flag == 0) {
            (void)rg_tipc_thr_hndshk(upgrd_cmd, ntv_sn);
            break;
        }
    }
    if (!LOCAL_UPGD_FLAG) {
        TIPC_DEBUG("LOCAL SN NOT INCLUDED");
        system(RM_TMP_VERSION);
        return SUCESS;
    }
    /*reinitialize local upgrade flag */
    LOCAL_UPGD_FLAG = 0;
    ret = rg_tipc_local_upgrd_prepare(version);
    if (ret == FAIL) {
        system(RM_TMP_VERSION);
        return FAIL;
    }

    ret = rg_tipc_mv_upgrd_file(version);
    if (ret == FAIL) {
        TIPC_DEBUG("MV-ERR.");
        return FAIL;
    }
    TIPC_DEBUG("MV-OK.");
    TIPC_DEBUG("SLEEP 10 SEC.");
    sleep(10);

    memset(sysupgrade_cmd, 0, sizeof(sysupgrade_cmd));
    snprintf(sysupgrade_cmd, sizeof(sysupgrade_cmd) - 1,
            "sysupgrade %s%s", TIPC_DOWNLOAD_DIR, version);
    TIPC_DEBUG("sysupgrade_cmd %s", sysupgrade_cmd);
    system(sysupgrade_cmd);

    return SUCESS;
}

int rg_tipc_send_process(unsigned char *upgrade_cmd,
                                 unsigned char *native_sn,
                                 unsigned char *version_name)
{
    struct list_head *pos;
    tipc_upgrade_node_t *tipc_un;
    struct timeval now;
    struct timespec outtime;
    struct sysinfo info;
    int ret;

    if (!upgrade_cmd || !native_sn || !version_name) {
        TIPC_DEBUG("upgrade_cmd or native_sn or version_name is NULL!");
        return FAIL;
    }

    pthread_mutex_lock(&mtx_tipc_upgrd_lock);
    list_for_each(pos, g_tipc_upgrade_list) {
        if (pos && ((tipc_upgrade_node_t *)pos)->flag == false) {
            ret = rg_tipc_client_socket_link(pos, upgrade_cmd, native_sn, version_name);
            if (ret == FAIL) {
                TIPC_DEBUG("Client link fail[%s]!", ((tipc_upgrade_node_t *)pos)->peersn);
                continue;
            }
            sysinfo(&info);
            ((tipc_upgrade_node_t *)pos)->time_out = info.uptime;
            ((tipc_upgrade_node_t *)pos)->flag = true;
//            TIPC_DEBUG("sn %s uptime %ld", ((tipc_upgrade_node_t *)pos)->peersn, ((tipc_upgrade_node_t *)pos)->time_out);
            g_tipc_upgrd_cnt++;
            if (g_tipc_upgrd_cnt > UPGRADE_MAX_CNT) {
                gettimeofday(&now, NULL);
                outtime.tv_sec = now.tv_sec + 360;        /* ³¬Ê±8min */
                outtime.tv_nsec = now.tv_usec * 1000;
                pthread_mutex_lock(&mtx_tipc_cond_lock);
                TIPC_DEBUG(" WAIT WAIT WAIT!!![%s]", ((tipc_upgrade_node_t *)pos)->peersn);
                g_tipc_cond_flag = true;
                pthread_cond_timedwait(&tipc_cond, &mtx_tipc_cond_lock, &outtime);
                g_tipc_cond_flag = false;
                TIPC_DEBUG("END END END[%d][%s]!!!", g_tipc_upgrd_cnt, ((tipc_upgrade_node_t *)pos)->peersn);
                g_tipc_upgrd_cnt--;
                pthread_mutex_unlock(&mtx_tipc_cond_lock);
            }
        }
    }
    pthread_mutex_unlock(&mtx_tipc_upgrd_lock);

    return SUCESS;
}

void rg_tipc_allnet_sync_upgrd_func(unsigned char *upgrade_cmd, char up_sn[][SN_LENGTH])
{
    int ret, i, j, k;
    unsigned char sn[20], native_sn[20], tmp_type[16], version_name[12], native_ip[20], rmt_type[64];
    struct json_object *jp = NULL, *list_all_p, *list_pair_p, *section, *sub_section;
    struct json_object *item_sn, *item_version, *item_type;
    unsigned char *wds_list = NULL, *tmp_softversion = NULL, *softver = NULL;
    unsigned char *version_type, *peer_version, *dev_type;
    tipc_upgrade_node_t tipc_un, *tmp_un;
    struct timespec outtime;

    /* Get native serial number */
    memset(native_sn, 0, sizeof(native_sn));
    rg_misc_read_file("/proc/rg_sys/serial_num", native_sn, sizeof(native_sn) - 1);

    tmp_softversion = rg_tipc_execute_buf(GET_TMP_SOFTVERSION);
    if (!tmp_softversion) {
        TIPC_DEBUG("Execute cmd[%s] error!", GET_TMP_SOFTVERSION);
        goto end;
    }
    softver = rg_tipc_execute_buf(TIPC_LOCAL_TAR_SOFTVER, tmp_softversion);
    if (!softver) {
        TIPC_DEBUG("Execute cmd[%s] error!", TIPC_LOCAL_TAR_SOFTVER);
        goto end;
    }

    memset(tmp_type, 0, sizeof(tmp_type));
    memset(version_name, 0, sizeof(version_name));
    ret = rg_filter_softversion_devtype(softver, tmp_type, version_name);
    if (ret == FAIL) {
        TIPC_DEBUG("Filter softversion error!");
        goto end;
    }
	if (rg_misc_popen(TIPC_GET_SOFTVER_FROM_PID, rmt_type, sizeof(rmt_type)) == -1) {
		TIPC_DEBUG("TIPC_GET_SOFTVER_FROM_PID err!!!");
        ret = FAIL;
        goto end;	
	}

    ret = rg_tipc_del_all_node_func();
    if (ret == SUCESS) {
        TIPC_DEBUG("DELETE g_tipc_upgrade_list SUCCESS.");
    }

    /* Get wds_list ==> list_all info */
    wds_list = rg_tipc_execute_buf(GET_WDS_LIST_ALL);
    if (!wds_list) {
        TIPC_DEBUG("Execute cmd[%s] error!", GET_WDS_LIST_ALL);
        goto end;
    }
    jp = json_tokener_parse((const char *)wds_list);
    if (!wds_list) {
        TIPC_DEBUG("Fail to get json string!");
        goto end;
    }

    list_all_p = json_object_object_get(jp, "list_all");
    if (!list_all_p) {
        TIPC_DEBUG("list_all is NULL!");
        goto end;
    }

    for(i = 0; i < json_object_array_length(list_all_p); i++) {
        section = json_object_array_get_idx(list_all_p, i);
        if (!section) {
            TIPC_DEBUG("section is NULL!");
            continue;
        }
        list_pair_p = json_object_object_get(section, "list_pair");
        if (!list_pair_p) {
            TIPC_DEBUG("list_pair_p is NULL!");
            continue;
        }
        for(j = 0; j < json_object_array_length(list_pair_p); j++) {
            sub_section = json_object_array_get_idx(list_pair_p, j);
            if (!sub_section) {
                TIPC_DEBUG("sub section is NULL!");
                continue;
            }

            item_sn = json_object_object_get(sub_section, "sn");
            if (!item_sn) {
                TIPC_DEBUG("item sn is NULL!");
                continue;
            }
            memset(sn, 0, sizeof(sn));
            strncpy(sn, (unsigned char *)(json_object_to_json_string(item_sn) + 1),
                strlen(json_object_to_json_string(item_sn)) - 2);
            /* Get dev_type string */
            item_type = json_object_object_get(sub_section, "dev_type");
            if (!item_type) {
                TIPC_DEBUG("item type is NULL!");
                continue;
            }
            dev_type = rg_tipc_strrpc((unsigned char *)json_object_to_json_string(item_type),
                strlen((char *)json_object_to_json_string(item_type)), "\"", "");
             /* Get softversion */
            item_version = json_object_object_get(sub_section, "softversion");
            if (!item_version) {
                TIPC_DEBUG("item version is NULL!");
                continue;
            }
            /* Get peer_version */
            peer_version = rg_tipc_strrpc((unsigned char *)json_object_to_json_string(item_version),
                strlen((char *)json_object_to_json_string(item_version)), "\"", "");
            if (!peer_version) {
                TIPC_DEBUG("peer version is NULL!");
                continue;
            }
            /* Convert softversion to int format */
            peer_version = rg_filter_ver_to_int(peer_version);
            if (!peer_version) {
                TIPC_DEBUG("peer version filter err!");
                continue;
            }

            /*
            * if doing allnet upgrade ,check all devices£»
            * if doing customized upgrade , check the devices been chosen
            */
            for (k = 0; k < MAX_SN_NUM; k++) {
                /* if doing allnet upgrade , check  directly */
                if (g_all_net_upgrade) {
                    TIPC_DEBUG("Checking  devices: [%s]", sn);
                } else if (!g_all_net_upgrade && memcmp(up_sn[k], sn, strlen(sn)) == 0) {
                    /* if doing customized upgrade, only when up_sn[k] equal sn ,begin to check */
                    TIPC_DEBUG("SN_[%s] match !!!", up_sn[k]);
                } else if (!g_all_net_upgrade && memcmp(up_sn[k], sn, strlen(sn)) != 0) {
                    continue;
                }

                /* begin to check */
                if (memcmp(sn, native_sn, strlen(native_sn)) == 0) {
                    /*if sn equal native_sn,do not add native_sn to upgrade_sn_list*/
                    TIPC_DEBUG("SN EQUAL EQUAL EQUAL!!!");
                    LOCAL_UPGD_FLAG = 1;
                    break;
                }
                if (strstr(rmt_type, dev_type) == NULL) {
                    /* if upgrae's type not equal to current dev_type, not create socket link. */
                    TIPC_DEBUG("peer devtype[%s] != upgrade devtype[%s]!", dev_type, tmp_type);
                    break;
                }
                if (rg_version_sync_check(version_name, peer_version) == false) {
                    /* if upgrae's version  not equal to current verison, not create socket link. */
                    TIPC_DEBUG("Device [sn:%s version:%s] does not need to sync the software version(%s)", sn, peer_version, version_name);
                    break;
                }

                /* Add the checked sn to upgrade_sn_list */
                memset(tipc_un.peersn, 0, TIPC_PEERSN_LEN);
                strncpy(tipc_un.peersn, sn , strlen(sn));
                tipc_un.flag = false;
                tipc_un.hs2_flag = false;
                ret = rg_tipc_add_list_func(&tipc_un);

                if (ret == FAIL) {
                    TIPC_DEBUG("tipc add list fail!");
                }
                break;
            }
        }
    }

    /*
     * repeatedly execute "rg_tipc_client_upgrade upgrade_req" cmd,
     * must be init global param
     */
    g_tipc_upgrd_cnt = 0;
    g_tipc_cond_flag = false;

    /* start send thread flag */
    ret = rg_tipc_send_process(upgrade_cmd, native_sn, tmp_softversion);
    if (ret == FAIL) {
        TIPC_DEBUG("send error.");
        goto end;
    }

    ret = rg_tipc_thr_hndshk_and_upgrd(UPGRADE_HS3_CMD, native_sn, tmp_softversion);
    if (ret == FAIL) {
        goto end;
    }

end:
    if (softver) {
        free(softver);
        softver = NULL;
    }
    if (tmp_softversion) {
        free(tmp_softversion);
        tmp_softversion = NULL;
    }
    if (wds_list) {
        free(wds_list);
        wds_list = NULL;
    }
    if (jp) {
        json_object_put(jp);
    }

    /* rm file in order to notify web or app */
    system(RM_TMP_VERSION);

    return;
}

int rg_tipc_message_process(struct sockaddr_in peeraddr)
{
    char up_sn[MAX_SN_NUM][SN_LENGTH];
    char cmd_msg[20];

    if (strlen(msg) <= 0){
        return 0;
    } else {
        memset(cmd_msg, 0, sizeof(cmd_msg));
        memset(up_sn, 0, sizeof(up_sn));
        memcpy(up_sn, rg_tipc_get_sn_from_msg(cmd_msg, sizeof(cmd_msg)), sizeof(up_sn));
        if (memcmp(cmd_msg, UPGRADE_REQ_CMD, strlen(UPGRADE_REQ_CMD)) == 0) {
            rg_tipc_allnet_sync_upgrd_func(UPGRADE_REQ_CMD, up_sn);
        }
    }

}


int rg_tipc_udp_recv_init()
{
    int i;
    int flag;
    socklen_t len;

    bzero(msg, SIZE);
    lisfd = socket(AF_INET, SOCK_DGRAM, 0);

    sock_bind(lisfd, 5005);
}

/**
 * rg_tipc_mbr_age_process: workqueue member ageing tasks
 */
void *rg_tipc_mbr_age_process()
{
    struct list_head *pos;
    tipc_upgrade_node_t *tmp;
    struct sysinfo info;

    tmp = NULL;
    while (1) {
        sleep(2);
        sysinfo(&info);
        list_for_each(pos, g_tipc_upgrade_list) {
            if (pos && ((tipc_upgrade_node_t *)pos)->flag == true
                && (long)(info.uptime - ((tipc_upgrade_node_t *)pos)->time_out) > UPGRADE_AGE_TIME) {
                ((tipc_upgrade_node_t *)pos)->flag = false;
                TIPC_DEBUG("AGEING AGEING AGEING WAKE UP[flag %d][%s]!!!",
                    ((tipc_upgrade_node_t *)pos)->flag, ((tipc_upgrade_node_t *)pos)->peersn);
                pthread_mutex_lock(&mtx_tipc_cond_lock);
                if (g_tipc_cond_flag == true) {
                    pthread_cond_signal(&tipc_cond);
                }
                pthread_mutex_unlock(&mtx_tipc_cond_lock);
                /* wait last signal finish */
                sleep(3);
            }
        }
    }

    return 0;
}

void *rg_tipc_recv_vergrd_process()
{
    int nbytes;
    struct sockaddr_in peeraddr;
    socklen_t len;

begin:
    if (lisfd <= 0) {
        rg_tipc_udp_recv_init();
        sleep(1);
        goto begin;
    }
    while (1) {
        memset(msg,0,sizeof(msg));
        nbytes = recvfrom(lisfd, msg, SIZE, 0, (struct sockaddr *)&peeraddr, &len);
        if (nbytes > 0) {
            rg_tipc_message_process(peeraddr);
            printf("UPGRADE-END.\n");
        }
    }
}

int main()
{
    struct sockaddr_tipc server_addr;
    struct sockaddr_tipc client_addr;
    socklen_t alen = sizeof(client_addr);
    int sd, ret;
    char buf[BUF_SIZE];
    unsigned int instant = 0;
    unsigned char mac[20], native_sn[16], sysupgrade_cmd[128];
    unsigned char *sn, *peer_sn, *str_token, *ipaddr, *version_name;
    unsigned char *upgrade_cmd, *tmp_softversion;
    unsigned char *sync_version;
    tipc_upgrade_node_t *tipc_un;
    tipc_upgrade_node_t tmp_un;
    pthread_t recv_upgrd_msg_thread;
    pthread_t send_syncver_start_thread;
    struct sysinfo info;
    struct timeval timeout={4,0};
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif
    /* initing global list */
    INIT_LIST_HEAD(g_tipc_upgrade_list);

    if (pthread_create(&recv_upgrd_msg_thread, NULL, rg_tipc_recv_vergrd_process, NULL) != 0) {
        TIPC_DEBUG("Create thread fail!");
        return FAIL;
    }

    if (pthread_create(&send_syncver_start_thread, NULL, rg_tipc_mbr_age_process, NULL) != 0) {
        TIPC_DEBUG("Create thread fail!");
        return FAIL;
    }

begin:
    memset(mac,0,sizeof(mac));
    rg_misc_read_file("/proc/rg_sys/sys_mac", mac, sizeof(mac) - 1);
    memset(native_sn, 0, sizeof(native_sn));
    rg_misc_read_file("proc/rg_sys/serial_num", native_sn, sizeof(native_sn) - 1);

    instant = rg_mist_mac_2_nodeadd(mac);
    if (instant == 0) {
        TIPC_DEBUG("error exit instant %d", instant);
        goto begin;
    }

    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAMESEQ;
    server_addr.addr.nameseq.type = SERVER_TYPE_UPGRADE;
    server_addr.addr.nameseq.lower = instant;
    server_addr.addr.nameseq.upper = instant;
    server_addr.scope = TIPC_ZONE_SCOPE;

    sd = socket(AF_TIPC, SOCK_RDM, 0);

    if (0 != bind(sd,(struct sockaddr *)&server_addr, sizeof(server_addr))){
        TIPC_DEBUG("Server: failed to bind port name");
        sleep(10);
        goto begin;
    }

    while (1) {
        memset(buf, 0, sizeof(buf));
        if (0 >= recvfrom(sd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&client_addr, &alen)) {
            perror("Server: unexpected message");
            continue;
        }
//        TIPC_DEBUG("buf %s", buf);

        upgrade_cmd = strtok(buf, "#");
//        TIPC_DEBUG("upgrade_cmd %s", upgrade_cmd);
        if (upgrade_cmd) {
            sn = strtok(NULL, "#");
//            TIPC_DEBUG("sn %s", sn);
            if (sn) {
                peer_sn = strtok(NULL, "#");
//                TIPC_DEBUG("peer_sn %s", peer_sn);
                if (peer_sn) {
                    version_name = strtok(NULL, "#");
//                    TIPC_DEBUG("version_name %s", version_name);
                }
            }
            if(tipc_cmd_check_symbol(sn) == FAIL || tipc_cmd_check_symbol(peer_sn) == FAIL || tipc_cmd_check_symbol(version_name) == FAIL){
                TIPC_DEBUG("Recv Illegal symbol");
                continue;
            }
        }
        
        if (!strncmp(upgrade_cmd, UPGRADE_REQ_CMD, strlen(upgrade_cmd))) {
            TIPC_DEBUG("Server recv %s", UPGRADE_REQ_CMD);
            setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
            if (0 > sendto(sd, buf, sizeof(buf) - 1, 0,
                (struct sockaddr *)&client_addr, sizeof(client_addr))) {
                perror("Server: failed to send!!!");
                continue;
            }

            /*
             * When the device receives an upgrade request,
             * if there is an upgrade package in the current device
             * TMP directory indicating that the current device is
             * upgrading, the upgrade request will be ignored.
             */
            ret = rg_tipc_check_upgrd_status();
            if (ret == FAIL) {
                TIPC_DEBUG("ERROR: DOING UPGRADE!!!");
                continue;
            }

            /*
             * If you confirm that you receive the current upgrade request,
             * you need to perform the following two actions:
             *     1. use tipc download tools; booting backgroud shell script. named
             *     "tipc_download_monitor.sh", downloaded bin to "/tmp/" path.
             *     2. echo 2/4 handshake stage to client, include the info of peer sn.
             */
            system(UPGRADE_CLEAR_CACHE);
            ret = rg_tipc_get_upgrade_bin(peer_sn, version_name);
            if (ret == FAIL) {
                TIPC_DEBUG("Get upgrade file fail!");
                system(RM_TMP_VERSION);
                continue;
            }
            (void)rg_tipc_client_upgrade_func(sn, peer_sn, UPGRADE_HS2_CMD);
        } else if (!strcmp(buf, UPGRADE_HS2_CMD)) {
            TIPC_DEBUG("Server recv %s", UPGRADE_HS2_CMD);
            memset(tmp_un.peersn, 0, TIPC_PEERSN_LEN);
            strncpy(tmp_un.peersn, sn, strlen(sn));
            tipc_un = rg_tipc_find_and_update_func(&tmp_un);
            if (!tipc_un) {
                TIPC_DEBUG("upgrade node NO FOUND!!!");
                continue;
            }
            /* no ageing member flag */
            tipc_un->flag = false;
            /* recv 2/4 handshake flag */
            tipc_un->hs2_flag = true;
            sysinfo(&info);
            tipc_un->time_out = info.uptime;

            /* sleep 3 seconds, wait last upgrade echo msg event */
            sleep(3);

            /*
             * if current sn task is waiting, send signal to unlock
             */
            pthread_mutex_lock(&mtx_tipc_cond_lock);
            if (g_tipc_cond_flag == true) {
                pthread_cond_signal(&tipc_cond);
                TIPC_DEBUG("HANDSHAKE HANDSHAKE HANDSHAKE WAKEUP!!!");
            }
            pthread_mutex_unlock(&mtx_tipc_cond_lock);

            /*
             * Can't send three handshakes here. we need to wait
             * until all the terminals have finished downloading
             * before shaking hands three times.
             */
            //(void)rg_tipc_client_upgrade_func(sn, peer_sn, UPGRADE_HS3_CMD);
        } else if (!strcmp(buf, UPGRADE_HS3_CMD)) {
            TIPC_DEBUG("Server recv %s", UPGRADE_HS3_CMD);
            tmp_softversion = rg_tipc_execute_buf(GET_TMP_SOFTVERSION);
            if (!tmp_softversion) {
                TIPC_DEBUG("There is no upgrade file in the TMP directory!");
                continue;
            }
            (void)rg_tipc_client_upgrade_func(sn, peer_sn, UPGRADE_HS4_CMD);
            /*
             * TODO: wait 10 seconds. The first device receives an tipc command.
             * If upgraded immediately, it may cause the associated the est device
             * fail to receive next tipc command.
             */
            TIPC_DEBUG("SLEEP 10 SEC.");
            sleep(10);

            memset(sysupgrade_cmd, 0, sizeof(sysupgrade_cmd));
            snprintf(sysupgrade_cmd, sizeof(sysupgrade_cmd) - 1, "sysupgrade \"/tmp/%s\"", tmp_softversion);
            TIPC_DEBUG("==>%s", sysupgrade_cmd);
            system(sysupgrade_cmd);
        } else if (!strcmp(buf, UPGRADE_HS4_CMD)) {
            TIPC_DEBUG("Server recv %s", UPGRADE_HS4_CMD);
            TIPC_DEBUG("UPGRADE BEGIN!!!");
        }
    }
}
