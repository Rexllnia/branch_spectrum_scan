#include <unistd.h>
#include <json-c/json.h>
#include "uf_plugin_intf.h"
#include "lib_unifyframe.h"
#include "DefaultConfig.h"

static uf_plugin_intf_t* g_intf;

static const char* default_config = "{\"isDefaultConfig\":true}";

char radio_name[MAX_BUF_SIZE];
char wds_bss[MAX_BUF_SIZE];
char cpe_wds_name[MAX_BUF_SIZE];
char manage_bss[MAX_BUF_SIZE];
char mtd_wds_mode[10];
char current_wdsmode = 0;
static char get_device_info(void) {
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
    if (!radiolist) {
        ret = FAIL;
        goto clean_up;
    }
    num_radios = json_object_array_length(radiolist);

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
            DF_DEBUG("Found WDS: radio_name=%s wds_bss=%s cpe_wds_name=%s\n", radio_name, wds_bss, cpe_wds_name);
        }

        /* Get support_manage */
        json_object* support_manage = json_object_object_get(radio, "support_manage");
        if (strcmp(json_object_get_string(support_manage), "true") == 0) {
            /* Get manage params */
            str = json_object_get_string(json_object_object_get(radio, "manage_bss"));
            strncpy(manage_bss, str, strnlen(str));
            DF_DEBUG("Found manage: manage_bss=%s\n", manage_bss);
        }

    }
    if ((strlen(radio_name) == 0) || (strlen(wds_bss) == 0) || (strlen(cpe_wds_name) == 0) || (strlen(manage_bss) == 0))
        ret = FAIL;
clean_up:
    /* Clean up */
    json_object_put(device_info);
    return ret;
}
static char mtd[8] = { 0 };
static void get_mtd_num(void) {
    char dev[10] = { 0 };
    int size = { 0 };
    char name[64] = { 0 };

    FILE* fp = fopen("/proc/mtd", "r");
    if (fp == NULL) {
        DF_DEBUG("Error opening /proc/mtd");
        return;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (sscanf(buffer, "%s %d %*s %63s", dev, &size, name) == 3) {
            if (strcmp(name, "\"product_info\"") == 0) {
                *strchr(dev, ':') = '\0';
                DF_DEBUG("mtd dev for product_info: %s\n", dev);
                strcpy(mtd, dev);
                break;
            }
        }
    }
    fclose(fp);
}

static char get_mtd_wdsmode(void) {

    char cmd_mtd[32] = { 0 };
    char output[1024] = { 0 };

    get_mtd_num();
    if (strlen(mtd) == 0) {
        return FAIL;
    }

    sprintf(cmd_mtd, "strings /dev/%s|grep WdsMode", mtd);

    FILE* fp = popen(cmd_mtd, "r");

    if (fp == NULL) {
        DF_DEBUG("Failed to run command\n");
        return FAIL;
    }

    while (fgets(output, sizeof(output), fp) != NULL) {
        DF_DEBUG("output=%s\n", output);
    }
    sscanf(output, "WdsMode=%s\n", mtd_wds_mode);
    DF_DEBUG("mtd_wds_mode=%s\n", mtd_wds_mode);
    pclose(fp);
    return SUCCESS;
}

static char* get_product_info_to_default_ssid(void) {

    FILE* fp = NULL;
    char* default_ssid = NULL;
    char cmd_mtd[64] = { 0 };
    char output[1024] = { 0 };
    char raw_mac[12] = { 0 };
    if (strcmp(mtd_wds_mode, "CPE") == 0) {
        strcpy(raw_mac, "PeerMac");
    } else {
        strcpy(raw_mac, "ethaddr");
    }

    sprintf(cmd_mtd, "strings /dev/%s|grep %s|awk -F \"=\" '{print $2}'", mtd, raw_mac);
    DF_DEBUG("cmd_mtd=%s\n", cmd_mtd);

    fp = popen(cmd_mtd, "r");

    if (fp == NULL) {
        DF_DEBUG("Failed to run command\n");
        return NULL;
    }

    while (fgets(output, sizeof(output), fp) != NULL) {
        DF_DEBUG("output=%s\n", output);
    }
    pclose(fp);
    char mac_concat[6] = { 0 };
    char ssid_prefix[16] = "@Ruijie-wds-";

    if (!output) {
        return NULL;
    }
    char mac[18] = { 0 };
    strncpy(mac, output, 17);
    DF_DEBUG("mac=%s\n", mac);
    mac[17] = '\0';

    char mac1[3] = { 0 };
    strncpy(mac1, mac + 12, 2);
    mac1[2] = '\0';

    char mac2[3] = { 0 };
    strncpy(mac2, mac + 15, 2);
    mac2[2] = '\0';

    sprintf(mac_concat, "%s%s", mac1, mac2);
    strcat(ssid_prefix, mac_concat);
    default_ssid = strdup(ssid_prefix);
    DF_DEBUG("default_ssid: %s\n", default_ssid);


    return default_ssid;
}

static int uci_wireless_get(char* e, char* section, char** output) {
    struct uci_context* ctx;
    struct uci_ptr ptr;
    char buf[64] = { 0 };

    *output = NULL;
    ctx = uci_alloc_context();
    DF_DEBUG("section:%s\n", section);
    DF_DEBUG("element:%s\n", e);
    snprintf(buf, sizeof(buf), "wireless.%s.%s", section, e);
    if (UCI_OK != uci_lookup_ptr(ctx, &ptr, buf, true)) {
        uci_free_context(ctx);
        uci_perror(ctx, "lookup failed");
        return -1;
    }
    if (ptr.o) {
        DF_DEBUG("%s: %s\n", e, ptr.o->v.string);
        *output = strdup(ptr.o->v.string);
    } else {
        DF_DEBUG("%s not found\n", e);
        uci_free_context(ctx);
        return -2;
    }
    uci_free_context(ctx);
    return 0;
}

static void unify_frame_invoke_admin_check(char** r, const char* param) {
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
    msg_obj->cmd = "get";
    msg_obj->module = "adminCheck";
    msg_obj->param = param;
    msg_obj->caller = "DefaultConfig"; /* 本次命令的调用者，如果是web则为pc，手机则为mobile，插件则为插件名 */

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

static char get_admin_check(void) {
    const char* json_str = NULL;
    char* output = NULL;
    char ret = 0;
    json_object* obj = json_object_new_object();

    json_object_object_add(obj, "password", json_object_new_string("admin"));
    json_object_object_add(obj, "type", json_object_new_string("noenc"));

    json_str = json_object_to_json_string(obj);
    DF_DEBUG("%s\n", json_str);

    unify_frame_invoke_admin_check(&output, json_str);
    DF_DEBUG("get_admin_check output=%s\n", output);

    json_object_put(obj);
    if (output) {

        json_object* root = uf_json_tokener_parse(output);
        if (!root) {
            DF_DEBUG("uf_json_tokener_parse(output)==NULL");
            free(output);
            return ret;
        }

        json_object* result_obj = json_object_object_get(root, "result");

        if (result_obj) {
            const char* result = json_object_get_string(result_obj);
            DF_DEBUG("result:%s\n", result);

            if (strncmp(result, "success", strlen(result)) == 0) {
                ret = 1;
            }
        }

        json_object_put(root);
        free(output);
    }

    return ret;
}

static void get_current_wds_mode(void) {

    char* output = NULL;
    if (uci_wireless_get("ApCliEnable", radio_name, &output) == -1) {
        return;
    }

    if ((output != NULL) && (strcmp(output, "1") == 0)) {
        current_wdsmode = STA;
        free(output);
    } else if ((output != NULL) && strcmp(output, "0") == 0) {
        current_wdsmode = AP;
        free(output);
    } else {
        current_wdsmode = AP;
    }
    DF_DEBUG("wdsmode: %d 1:AP 0:STA\n", current_wdsmode);
}

static char* get_current_ssid(void) {
    char* output = NULL;
    char* section = NULL;
    char element[12] = { 0 };

    get_current_wds_mode();
    if (current_wdsmode == STA) {
        strcpy(element, "ApCliSsid");
        section = radio_name;
    } else {
        strcpy(element, "ssid");
        section = wds_bss;
    }

    DF_DEBUG("section:%s", section);
    DF_DEBUG("wds_bss:%s", wds_bss);
    if (uci_wireless_get(element, section, &output) == -1) {
        return NULL;
    }
    if (output) {
        return output;
    } else {
        return NULL;
    }
}

static char* get_default_config() {
    char* current_ssid = NULL;
    char* default_ssid = NULL;
    char* Default_config_json = NULL;
    json_object* json_str = NULL;
    char is_admin = 0;
    json_str = json_object_new_object();

    if (get_device_info() == FAIL) {
        goto false_default;
    }

    if (get_mtd_wdsmode() == FAIL) {
        DF_DEBUG("get_mtd_wdsmode");
        goto false_default;
    }

    is_admin = get_admin_check();

    if (is_admin != TRUE) {
        DF_DEBUG("no default key check");
        goto false_default;
    }

    current_ssid = get_current_ssid();

    default_ssid = get_product_info_to_default_ssid();

    DF_DEBUG("default_ssid=%s current_ssid=%s", default_ssid, current_ssid);


    if (current_ssid == NULL) {
        json_object_object_add(json_str, "isDefaultConfig", json_object_new_boolean(FALSE));
    } else if (strcmp(current_ssid, default_ssid) == 0) {
        json_object_object_add(json_str, "isDefaultConfig", json_object_new_boolean(TRUE));
    } else {
        json_object_object_add(json_str, "isDefaultConfig", json_object_new_boolean(FALSE));
    }
    Default_config_json = strdup(json_object_to_json_string(json_str));
    DF_DEBUG("Default_config_json=%s ", Default_config_json);
    json_object_put(json_str);

    if (current_ssid)
        free(current_ssid);
    if (default_ssid)
        free(default_ssid);
    return Default_config_json;

false_default:
    json_object_object_add(json_str, "isDefaultConfig", json_object_new_boolean(FALSE));
    Default_config_json = strdup(json_object_to_json_string(json_str));
    json_object_put(json_str);
    return Default_config_json;
}


static int handle_fuc_DefaultConfig(uf_plugin_attr_t* attr, char** rbuf) {
    int ret = 0;

    switch (attr->cmd) {
    case(UF_CMD_GET):
        DF_DEBUG("UF_CMD_GET \n");
        *rbuf = get_default_config();
        if (*rbuf == NULL) {
            DF_DEBUG("error:malloc failed!");
        }
        break;
    default:
        DF_DEBUG("default \n");
        break;
    }
    DF_DEBUG("<===============handle_fuc_DefaultConfig end====================>");
    return ret;
}

void module_init_DefaultConfig(uf_plugin_intf_t* intf) {

    strcpy(intf->name, "DefaultConfig");
    intf->fuc = (uf_handle_fuc) handle_fuc_DefaultConfig;
    g_intf = intf;
    DF_DEBUG("<======Init DefaultConfig=========>");
    return;
}
