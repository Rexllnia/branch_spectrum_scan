/*
 * Copyright(C) 2023 Ruijie Network. All rights reserved.
 */
 /*
  * rg_wds_frame.c
  * Original Author:  huangyongyuan@ruijie.com.cn, 2023-9-18
  *
  * est unified framework api
  *
  */
#include "rg_wds_frame.h"


static void unify_frame_invoke(char** r, char* cmd, char* module, char* param, int ctype) {
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

    msg_obj->ctype = ctype; /* 调用类型 ac/dev/.. */
    msg_obj->cmd = cmd;
    msg_obj->module = module;
    msg_obj->param = param;
    msg_obj->caller = "rg_wds_gpio"; /* 本次命令的调用者，如果是web则为pc，手机则为mobile，插件则为插件名 */

    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret) {
        *r = strdup("unify_frame_invoke failed!");
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

void unify_frame_invoke_dev_config(char** r, char* cmd, char* module, char* param) {
    unify_frame_invoke(r, cmd, module, param, UF_DEV_CONFIG_CALL);
}
void unify_frame_invoke_dev_sta(char** r, char* cmd, char* module, char* param) {
    unify_frame_invoke(r, cmd, module, param, UF_DEV_STA_CALL);
}


