#include "one_click_conn.h"

char radio_name[MAX_BUF_SIZE];
char wds_bss[MAX_BUF_SIZE];
char cpe_wds_name[MAX_BUF_SIZE];
char manage_bss[MAX_BUF_SIZE];
char wdsmode = 0;

char OCC_ON_CMD[64] = { 0 };
char OCC_OFF_CMD[64] = { 0 };

char OCC_LOW_TXPOWER_CMD[64] = { 0 };
char OCC_RECOVER_TXPOWER_CMD[64] = { 0 };

char KILL_RANDOM_CHANNL[64] = { 0 };

int old_txpower_value = 0;

void iwpriv_cmd(char* ifname, char* cmd, int request) {
    char data[255] = { 0 };
    char name[25] = { 0 };
    int socket_id;
    struct iwreq wrq;
    int ret;
    /* open socket based on address family: AF_INET */
    socket_id = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_id < 0) {
        OneCC_INFO("\nrtuser::error::Open socket error!\n\n");
        return -1;
    }
    /* interface name as "rai0" */
    sprintf(name, "%s", ifname);

    /* iwpriv rai0 set cmd */
    memset(&wrq, 0x00, sizeof(wrq));
    memset(data, 0x00, sizeof(data));
    strcpy(data, cmd);
    strcpy(wrq.ifr_name, name);
    wrq.u.data.length = strlen(data) + 1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;
    ret = ioctl(socket_id, request, &wrq);
    if (ret != 0) {
        OneCC_INFO("rtuser::error::set %s\n", cmd);
    }
    close(socket_id);
}

static char get_dev_info(void) {
    int i;
    const char* str = NULL;
    int num_radios = 0;
    char ret = SUCCESS;
    /* Parse JSON file */
    json_object* device_info = json_object_from_file(DEVICE_INFO_FILE);
    if (!device_info) {
        return FAIL;
    }
    /* Get wireless object */
    json_object* wireless = json_object_object_get(device_info, "wireless");
    if (!wireless) {
        ret = FAIL;
        goto clean_up;
    }
    /* Get radiolist array */
    json_object* radiolist = json_object_object_get(wireless, "radiolist");
    num_radios = json_object_array_length(radiolist);
    if (!radiolist) {
        ret = FAIL;
        goto clean_up;
    }
    /* Iterate radios */
    for (i = 0; i < num_radios; i++) {
        json_object* radio = json_object_array_get_idx(radiolist, i);

        /* Get support_wds */
        json_object* support_wds = json_object_object_get(radio, "support_wds");
        if (strcmp(json_object_get_string(support_wds), "true") == 0) {
            /* Get WDS params */
            str = json_object_get_string(json_object_object_get(radio, "name"));
            strncpy(radio_name, str, strlen(str));
            str = json_object_get_string(json_object_object_get(radio, "wds_bss"));
            strncpy(wds_bss, str, strlen(str));
            str = json_object_get_string(json_object_object_get(radio, "cpe_bridge_interface"));
            strncpy(cpe_wds_name, str, strlen(str));
            OneCC_INFO("Found WDS: radio_name=%s wds_bss=%s cpe_wds_name=%s\n", radio_name, wds_bss, cpe_wds_name);
        }

        /* Get support_manage */
        json_object* support_manage = json_object_object_get(radio, "support_manage");
        if (strcmp(json_object_get_string(support_manage), "true") == 0) {
            /* Get manage params */
            str = json_object_get_string(json_object_object_get(radio, "manage_bss"));
            strncpy(manage_bss, str, strnlen(str));
            OneCC_INFO("Found manage: manage_bss=%s\n", manage_bss);
        }
    }
    if ((strlen(radio_name) == 0) || (strlen(wds_bss) == 0) || (strlen(cpe_wds_name) == 0) || (strlen(manage_bss) == 0))
        ret = FAIL;
clean_up:
    /* Clean up */
    json_object_put(device_info);
    return ret;
}

static void unifiy_get_onecc(char** r) {
    uf_cmd_msg_t* msg_obj = NULL;
    const char* json_str = NULL;
    int ret;
    char* rbuf;

    rbuf = NULL;
    msg_obj = (uf_cmd_msg_t*) malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        ret = -1;
        *r = strdup("memory full!");
        return;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->ctype = UF_DEV_CONFIG_CALL; /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "get";
    msg_obj->module = "OneClickConn";
    msg_obj->param = NULL;
    msg_obj->caller = "OneClickConn"; /* 本次命令的调用者，如果是web则为pc，手机则为mobile，插件则为插件名 */

    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret) {
        *r = strdup("get OneClickConn failed!");
        free(msg_obj);
        if (rbuf) {
            free(rbuf);
        }
        return;
    }
    free(msg_obj);
    *r = rbuf;
    return;
}

static void unifiy_invoke_radio(char** r, char* cmd, char* param) {
    uf_cmd_msg_t* msg_obj = NULL;
    const char* json_str = NULL;
    int ret;
    char* rbuf;

    rbuf = NULL;
    msg_obj = (uf_cmd_msg_t*) malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        ret = -1;
        *r = strdup("memory full!");
        return;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->ctype = UF_DEV_CONFIG_CALL; /* 调用类型 ac/dev/.. */
    msg_obj->cmd = cmd;
    msg_obj->module = "radio";
    msg_obj->param = param;
    msg_obj->caller = "OneClickConn"; /* 本次命令的调用者，如果是web则为pc，手机则为mobile，插件则为插件名 */

    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret) {
        *r = strdup("get radio failed!");
        free(msg_obj);
        if (rbuf) {
            free(rbuf);
        }
        return;
    }
    free(msg_obj);
    *r = rbuf;
    return;
}

static void get_tx_power(void) {
    char* radio_json = NULL;
    json_object* txpower = NULL;
    unifiy_invoke_radio(&radio_json, "get", NULL);
    struct json_object* json_obj = json_tokener_parse(radio_json);
    OneCC_INFO("json_str==%s\n", json_object_to_json_string(json_obj));
    json_object* radioList = json_object_object_get(json_obj, "radioList");
    int i, radiolist_len = json_object_array_length(radioList);
    for (i = 0; i < radiolist_len; i++) {
        json_object* radio = json_object_array_get_idx(radioList, i);
        if (strcmp(json_object_get_string(json_object_object_get(radio, "type")), "5G") == 0) {
            /* radiolist找到type为5G的对象 */
            txpower = json_object_object_get(radio, "txpower");
        }
    }

    if (!txpower) {
        OneCC_ERROR("Error: unable to find 5G txpower\n");
        exit(1);
    }

    const char* txpower_str = json_object_get_string(txpower);
    OneCC_INFO("txpower_str==%s\n", txpower_str);
    if (strcmp(txpower_str, "auto") == 0) {
        old_txpower_value = 100;
    } else {
        old_txpower_value = atoi(txpower_str);
    }
    OneCC_INFO("old_txpower_value==%d\n", old_txpower_value);

    json_object_put(json_obj);
    free(radio_json);
}

unsigned char get_onecc_status(void) {
    char* one_cc_status_json = NULL;
    unsigned char ret = 0;
    unifiy_get_onecc(&one_cc_status_json);

    struct json_object* json_obj = json_tokener_parse(one_cc_status_json);
    struct json_object* enable_obj = NULL;

    json_object_object_get_ex(json_obj, "enable", &enable_obj);

    OneCC_INFO("enable: %d\n", json_object_get_boolean(enable_obj));
    ret = json_object_get_boolean(enable_obj);
    json_object_put(json_obj);
    free(one_cc_status_json);
    return ret;
}

static void dev_sta_switch_mode(char** r, const char* param) {
    uf_cmd_msg_t* msg_obj = NULL;

    const char* json_str = NULL;
    int ret;
    char* rbuf;

    rbuf = NULL;
    msg_obj = (uf_cmd_msg_t*) malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        ret = -1;
        *r = strdup("memory full!");
        return;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->ctype = UF_DEV_STA_CALL; /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "set";
    msg_obj->module = "wdsmode_switch";
    msg_obj->param = param;
    msg_obj->caller = "OneClickConn"; /* 本次命令的调用者，如果是web则为pc，手机则为mobile，插件则为插件名 */

    OneCC_INFO("param : %s\n", param);

    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret) {
        *r = strdup("set wdsmode_switch failed!");
        free(msg_obj);
        if (rbuf) {
            free(rbuf);
        }
        return;
    }
    free(msg_obj);
    *r = rbuf;
    return;
}
unsigned char  get_popen_output(char* cmd, char* output) {
    OneCC_INFO("cmd:%s\n", cmd);
    FILE* fp = popen(cmd, "r");
    char buf[256] = { 0 };
    if (fp == NULL) {
        OneCC_INFO("Failed to run command\n");
        return FAIL;
    }
    if (output == NULL) {
        pclose(fp);
        return SUCCESS;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        strcat(output, buf);
    }
    pclose(fp);
    return SUCCESS;
}

int uci_wireless_get(char* e, char* section, char** output) {
    struct uci_context* ctx;
    struct uci_ptr ptr;
    char buf[64] = { 0 };

    *output = NULL;
    ctx = uci_alloc_context();
    OneCC_INFO("section:%s\n", section);
    snprintf(buf, sizeof(buf), "wireless.%s.%s", section, e);
    if (UCI_OK != uci_lookup_ptr(ctx, &ptr, buf, true)) {
        uci_free_context(ctx);
        uci_perror(ctx, "lookup failed");
        return -1;
    }
    if (ptr.o) {
        OneCC_INFO("%s: %s\n", e, ptr.o->v.string);
        *output = strdup(ptr.o->v.string);
    } else {
        OneCC_ERROR("%s not found\n", e);
        uci_free_context(ctx);
        return -2;
    }
    uci_free_context(ctx);
    return 0;
}
void startOneCC(void) {
    int time = 0;
    iwpriv_cmd(wds_bss, OCC_ON_CMD, RTPRIV_IOCTL_SET);
    iwpriv_cmd(wds_bss, OCC_LOW_TXPOWER_CMD, RTPRIV_IOCTL_SET);
    get_popen_output(LED_SEND_MESSAGE(OCC_LED_ON), NULL);
    OneCC_INFO("Start One Click Connect ...\n");
    while (time < 3 * 60) {/* 一键易联三分钟 */
        sleep(1);
        time++;
    }
}
void get_dev_mode(void) {

    char* output = NULL;
    if (uci_wireless_get("ApCliEnable", radio_name, &output) == -1) {
        return;
    }

    if ((output != NULL) && (strcmp(output, "1") == 0)) {
        wdsmode = STA;
        free(output);
    } else if ((output != NULL) && strcmp(output, "0") == 0) {
        wdsmode = AP;
        free(output);
    } else {
        wdsmode = AP;
    }
    OneCC_INFO("wdsmode: %d 1:AP 0:STA\n", wdsmode);
}
int occ_iwpriv() {
    char* ciphertext = NULL;
    char* output = NULL;
    char* pswitchmode_set = NULL;
    json_object* json_str = NULL;


    if (get_onecc_status() == false) {
        OneCC_ERROR("one click connetc function off\n");
        return -1;
    }

    switch (wdsmode) {
    case AP:
        startOneCC();
        break;
    case STA:
        json_str = json_object_new_object();
        if (uci_wireless_get("ApCliWPAPSK", radio_name, &output) != 0) {
            json_object_put(json_str);
            return -1;
        }

        ciphertext = rg_crypto_buf_encrypt(output, strlen(output), 'c');
        if (ciphertext == NULL) {
            OneCC_ERROR("rg_crypto_buf_encrypt failed\n");
            return -1;
        }
        OneCC_INFO("ciphertext = [%s]\n", ciphertext);

        json_object_object_add(json_str, "pw", json_object_new_string(ciphertext));
        rg_crypto_buf_free(ciphertext);   /* 释放内存 */
        free(output);

        if (uci_wireless_get("country", radio_name, &output) != 0) {
            return -1;
        }

        json_object_object_add(json_str, "wdsmode", json_object_new_string("ap"));
        json_object_object_add(json_str, "country", json_object_new_string(output));
        free(output);
        if (uci_wireless_get("ApCliSsid", radio_name, &output) != 0) {
            json_object_put(json_str);
            return -1;
        }
        json_object_object_add(json_str, "ssidName", json_object_new_string(output));
        free(output);

        dev_sta_switch_mode(&pswitchmode_set, json_object_to_json_string(json_str));
        free(pswitchmode_set);

        json_object_put(json_str);
        startOneCC();
        break;
    default:
        break;
    }

    return 0;
}

int onecc_get_cpe_wds_pair_list_stations(const char* ifname) {
    rj_ex_ioctl_t ioc;
    rj_stainfo_t stainfo;
    rj_stainfo_t* asso_info = NULL;
    int ret = FAIL;
    char msg[MAC_TAB_LEN];
    int msg_len = sizeof(msg);
    int msg_type;
    RJ80211_MAC_TABLE* sta_info = NULL;

    msg_type = RJ_WAS_SHOW_APLCLI_INFO_EN;
    OneCC_INFO("ifname %s\n", ifname);
    ret = was_ext_ioctl_msg(msg, msg_len, ifname, msg_type, false);
    if (ret != WAS_E_NONE) {
        OneCC_ERROR("wlanconfig result is failed\n");
        return FAIL;
    }
    if (!msg) {
        OneCC_ERROR("%s:buf is null!", __func__);
        return FAIL;
    }

    asso_info = (rj_stainfo_t*) msg;

    return !asso_info->is_reassoc;/* 1：already bridged 0：Bridge disconnect */
}

void one_cc_atexit() {
    /* Disable one-click connection */
    iwpriv_cmd(wds_bss, OCC_OFF_CMD, RTPRIV_IOCTL_SET);
    iwpriv_cmd(wds_bss, OCC_RECOVER_TXPOWER_CMD, RTPRIV_IOCTL_SET);
    get_popen_output(LED_SEND_MESSAGE(OCC_LED_OFF), NULL);
    exit(0);
    OneCC_INFO(" one click conn process end\n");
}

void one_cc_exithandler(int signum) {
    one_cc_atexit();
}

void get_onecc_cmd(void) {

    snprintf(OCC_ON_CMD, sizeof(OCC_ON_CMD), "one_click_status=1", wds_bss);
    snprintf(OCC_OFF_CMD, sizeof(OCC_OFF_CMD), "one_click_status=0", wds_bss);

    snprintf(OCC_LOW_TXPOWER_CMD, sizeof(OCC_LOW_TXPOWER_CMD), "PowerDropCtrl=%d", OCC_LOW_TXPOWER);
    snprintf(OCC_RECOVER_TXPOWER_CMD, sizeof(OCC_RECOVER_TXPOWER_CMD), "PowerDropCtrl=%d", old_txpower_value);

    snprintf(KILL_RANDOM_CHANNL, sizeof(KILL_RANDOM_CHANNL), "killall wds_random_chan.sh");
}


int main() {
    int ret = 0;
    signal(SIGTERM, one_cc_exithandler);/* kill -15 killall*/
    signal(SIGINT, one_cc_exithandler);/* kill -2 ctl + C*/
    atexit(one_cc_atexit);
    log_level_t g_log_lv = LOG_INFO1;
    ret = onecc_log_init(ONE_CC_LOG_FILE, ONE_CC_LOG_FILE_SIZE, g_log_lv);
    if (ret != 0) {
        OneCC_ERROR("onecc_log_init() failed!!!");
        return -1;
    }
    OneCC_INFO("enter one_click_con\n");
    get_popen_output(LED_SEND_MESSAGE(OCC_LED_SWITCH), NULL);
    if (get_dev_info() == FAIL) {
        return 0;
    }
    get_dev_mode();
    get_tx_power();/* 获取当前功率*/
    get_onecc_cmd();
    if (wdsmode == STA) {
        if (onecc_get_cpe_wds_pair_list_stations(cpe_wds_name) == SUCCESS) {
            OneCC_INFO("The CPE has been bridged and cannot be easily connected by one click\n");
            return 0;
        }
    }
    system(KILL_RANDOM_CHANNL);
    OneCC_INFO("%s", KILL_RANDOM_CHANNL);
    occ_iwpriv();
    return 0;
}