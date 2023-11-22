#include "spctrm_scn24_rlog.h"

static struct ubus_context *ctx;
static struct blob_buf b;
static int module_enable_result;
static int upload_stream_result;
enum
{
    RESULT,
    __RESULT_MAX
};
static const struct blobmsg_policy result_policy[] = {
    [RESULT] = {.name = "result", .type = BLOBMSG_TYPE_STRING},
};
 
static void rlog_module_enable_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[__RESULT_MAX];
 
    blobmsg_parse(result_policy, ARRAY_SIZE(result_policy), tb, blob_data(msg), blob_len(msg));
    module_enable_result = atoi(blobmsg_get_string(tb[RESULT]));  
    debug("%d",upload_stream_result);   
}

int spctrm_scn24_rlog_module_enable(const char *module) 
{
    const char *ubus_socket = NULL;
    unsigned int id;
    int ret;
    int timeout = 30;
    ctx = ubus_connect(ubus_socket);
    
    if (module == NULL) {
        return;
    }

    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return FAIL;
    }
 
    blob_buf_init(&b, 0);
 
    blobmsg_add_string(&b,"module",module);
 
    ret = ubus_lookup_id(ctx, "rlog", &id);
    if (ret != UBUS_STATUS_OK) {
        debug("lookup rlog failed\n");
        return FAIL;
    } else {
        debug("lookup rlog successs\n");
    }
    ubus_invoke(ctx, id, "module_enable", b.head, rlog_module_enable_cb, NULL, timeout * 1000);
    ubus_free(ctx);

    sleep(1);
    return SUCCESS;
}
static void rlog_upload_stream_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[__RESULT_MAX];
    blobmsg_parse(result_policy, ARRAY_SIZE(result_policy), tb, blob_data(msg), blob_len(msg));
    upload_stream_result = atoi(blobmsg_get_string(tb[RESULT])); 
    debug("%d",upload_stream_result);   
}
int spctrm_scn24_rlog_upload_stream(char *module,char *data) 
{
    const char *ubus_socket = NULL;
    unsigned int id;
    int ret;
    int timeout = 30;

    if (module == NULL || data == NULL) {
        return FAIL;
    }

    ctx = ubus_connect(ubus_socket);
    
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return FAIL;
    }
 
    blob_buf_init(&b, 0);
 
    blobmsg_add_string(&b,"module", module);
    blobmsg_add_string(&b,"server","http://apidemo.rj.link/service/api/warnlog?sn=MACCEG20WJL01");
    blobmsg_add_string(&b,"data", data);
 
    ret = ubus_lookup_id(ctx, "rlog", &id);
    if (ret != UBUS_STATUS_OK) {
        debug("lookup rlog failed\n");
        return FAIL;
    } else {
        debug("successs\n");
    }
    ubus_invoke(ctx, id, "upload_stream", b.head, rlog_upload_stream_cb, NULL, timeout * 1000);
    ubus_free(ctx);
    sleep(1);
    return SUCCESS;
}