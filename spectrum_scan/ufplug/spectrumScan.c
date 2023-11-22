#include <json-c/json.h>  
#include <string.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include "uf_plugin_intf.h"  
#include "libubus.h"
char g_spctrm_scn_ubus_rbuf[4096];
static int spctrm_scn_ubus_invoke_handle_cb(struct ubus_request *req,int type, struct blob_attr *msg)
{
   strcpy(g_spctrm_scn_ubus_rbuf,blobmsg_format_json(msg,true));
}
static int spctrm_scn_fnc(uf_plugin_attr_t *attr, char **rbuf)
{
    int ret;
    const char *para_obj;
    int id;
    struct ubus_context *ctx;
    static struct blob_buf b;
    char json_string[1024];

    blob_buf_init(&b, 0);

    // if (attr == NULL) {
    //     return -1;
    // }

    // if (attr->para_obj == NULL) {
    //     return -1;
    // }

    para_obj = NULL;
    para_obj = json_object_get_string(attr->para_obj);
    // if (para_obj == NULL) {
    //     return -1;
    // }

    switch (attr->cmd) {
    case UF_CMD_ADD:
        /* dev_sta add */
        break;
    case UF_CMD_GET:
        uf_ubus_lock();
        ctx = ubus_connect(NULL);
        ubus_lookup_id(ctx,"spctrm_scn24",&id);
        ubus_invoke(ctx, id, "get", NULL, spctrm_scn_ubus_invoke_handle_cb, 0, 3000);
        ubus_free(ctx);
        uf_ubus_unlock();
        *rbuf = strdup(g_spctrm_scn_ubus_rbuf);
        /* dev_sta get */
        break;
    case UF_CMD_DEL:
        /* dev_sta del */
        break;
    case UF_CMD_SET:
        if (para_obj == NULL) {
            return -1;
        }
        uf_ubus_lock();
        ctx = ubus_connect(NULL);
        ubus_lookup_id(ctx,"spctrm_scn24",&id);
        
        blobmsg_add_json_from_string(&b,para_obj);
        ubus_invoke(ctx, id, "set", b.head, spctrm_scn_ubus_invoke_handle_cb, 0, 3000);
        ubus_free(ctx);
        uf_ubus_unlock();
        // strcpy(json_string,json_object_to_json_string(para_obj));
        *rbuf = strdup(g_spctrm_scn_ubus_rbuf);    
        /* dev_sta set */
        break;
    case UF_CMD_UPDATE:
        break;
    case UF_CMD_GET_DEFAULT:
        break;
    default:
        break;
    }
    return 0;
}  
void module_init_spectrum_scan(uf_plugin_intf_t *intf)  
{  
    if (intf == NULL) {
        return;
    }
    strcpy(intf->name, "spectrumScan24");
    intf->fuc = (uf_handle_fuc)spctrm_scn_fnc;
    return ;  
} 