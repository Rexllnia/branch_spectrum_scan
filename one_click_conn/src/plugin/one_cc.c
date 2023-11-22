#include <unistd.h>
#include <json-c/json.h>
#include "uf_plugin_intf.h"
#include "lib_c/libstring.h"
#include "one_cc.h"

static uf_plugin_intf_t* g_intf;

static const char* default_config = "{\"enable\":true}";

static void set_switch(struct json_object* p_obj, char** rbuf) {
    char cmd[128] = { 0 };
    int ret = 0;
    struct json_object* enable_obj = NULL;
    const char* content = json_object_to_json_string(p_obj);
    OCC_DEBUG("content=%s", content);
    if (param_safety_check(content) != 0) {
        OCC_DEBUG("param_safety_check error");
        *rbuf = strdup("{\"err\":\"warning!!param is not safe.\"}");
        return -1;
    }
    *rbuf = strdup(json_object_get_string(p_obj));

    json_object_object_get_ex(p_obj, "enable", &enable_obj);

    OCC_DEBUG("enable: %d\n", json_object_get_boolean(enable_obj));
    ret = json_object_get_boolean(enable_obj);
    if (ret == FALSE) {
        snprintf(cmd, sizeof(cmd), "killall %s", OCC_PROAM);
        OCC_DEBUG("cmd=%s\n", cmd);
        system(cmd);
    }
}

static int handle_fuc_OneClickConn(uf_plugin_attr_t* attr, char** rbuf) {
    int ret = 0;

    OCC_DEBUG("<===============handle_fuc_OneClickConn starting===============>");
    switch (attr->cmd) {
    case(UF_CMD_SET):
        set_switch(attr->para_obj, rbuf);
        break;
    case(UF_CMD_GET_DEFAULT):
        *rbuf = strdup(default_config);
        if (*rbuf == NULL) {
            OCC_DEBUG("error:malloc failed!");
        }
        break;
    default:
        break;
    }
    OCC_DEBUG("<===============handle_fuc_OneClickConn end====================>");
    return ret;
}

void module_init_OneClickConn(uf_plugin_intf_t* intf) {

    strcpy(intf->name, "OneClickConn");
    intf->fuc = (uf_handle_fuc) handle_fuc_OneClickConn;
    g_intf = intf;
    OCC_DEBUG("<======end OneClickConn=========>");
    return;
}
