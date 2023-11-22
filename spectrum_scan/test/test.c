#include <json-c/json.h>  
#include <string.h>
#include <libubox/blobmsg_json.h>
#include "uf_plugin_intf.h"  
#include "libubus.h"
char g_spctrm_scn_ubus_rbuf[4096];
static int spctrm_scn_ubus_invoke_handle_cb(struct ubus_request *req,int type, struct blob_attr *msg)
{
   strcpy(g_spctrm_scn_ubus_rbuf,blobmsg_format_json(msg,true));
}
int main()
{
    int ret;
    const char *para_obj;
    int id;
    struct ubus_context *ctx;
    static struct blob_buf b;

    blob_buf_init(&b, 0);

    ctx = ubus_connect(NULL);
    ubus_lookup_id(ctx,"spctrm_scn24",&id);
    ubus_invoke(ctx, id, "get", NULL, spctrm_scn_ubus_invoke_handle_cb, 0, 3000);
    printf("%s",g_spctrm_scn_ubus_rbuf);
    ubus_free(ctx);
     
}
