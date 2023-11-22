#include "rg_wds.h"

int g_timer_period = 15 *1000;
struct uloop_timeout send_multi_timer;
struct uloop_timeout wds_all_proc_timer;


static void wds_send_multi_timer(void);
static int rg_wds_ubus_get_info_methods(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg);

static int rg_wds_ubus_set_info_methods(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg);

static struct ubus_context *rg_wds_ubus_ctx = NULL;
static struct blob_buf rg_wds_ubus_b;
static struct uloop_timeout rg_wds_ubus_connect_timer;

static const struct blobmsg_policy rg_wds_ubus_get_policy[RG_WDS_UBUS_GET_MAX] = {
    [RG_WDS_UBUS_GET_ALL_STA] = { .name = RG_WDS_UBUS_GET_ALL_STA_CODE, .type = BLOBMSG_TYPE_STRING },
    [RG_WDS_UBUS_GET_ALL_RG_STA] = { .name = RG_WDS_UBUS_GET_ALL_RG_STA_CODE, .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy rg_wds_ubus_set_policy[RG_WDS_UBUS_SET_MAX] = {
    [RG_WDS_UBUS_SET_LOG_UPDATE_PERIOD] = { .name = RG_WDS_UBUS_SET_LOG_UPDATE_PERIOD_CODE, .type = BLOBMSG_TYPE_INT32 },
};

static const struct ubus_method rg_wds_ubus_methods[] = {
    UBUS_METHOD(RG_WDS_UBUS_GET_METHOD_INFO, rg_wds_ubus_get_info_methods, rg_wds_ubus_get_policy),
    UBUS_METHOD(RG_WDS_UBUS_SET_METHOD_INFO, rg_wds_ubus_set_info_methods, rg_wds_ubus_set_policy),
};

static struct ubus_object_type rg_wds_ubus_object_type =
    UBUS_OBJECT_TYPE(RG_WDS_UBUS_OBJECT_INFO, rg_wds_ubus_methods);

static struct ubus_object rg_wds_ubus_object = {
    .name = RG_WDS_UBUS_OBJECT_INFO,
    .type = &rg_wds_ubus_object_type,
    .methods = rg_wds_ubus_methods,
    .n_methods = ARRAY_SIZE(rg_wds_ubus_methods),
};

/* sta 获取信息方法 */
static int rg_wds_ubus_get_info_methods(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
    struct blob_attr *tb[RG_WDS_UBUS_GET_MAX];
    char *tmp_param = NULL;

    DEBUG("rg_wds_ubus_get_info_methods\n");
    blobmsg_parse(rg_wds_ubus_get_policy, ARRAY_SIZE(rg_wds_ubus_get_policy), tb, blob_data(msg), blob_len(msg));
    if (tb[RG_WDS_UBUS_GET_ALL_STA]) {
        tmp_param = blobmsg_data(tb[RG_WDS_UBUS_GET_ALL_STA]);
        DEBUG("rg_wds_ubus_get_info_methods param:\"%s\"\n", tmp_param);
        if (strncmp(tmp_param, "networkId_notify", strlen("networkId_notify")) != 0) {
            DEBUG("ubus no match!");
            return -1;
        }
        /*
        g_timer_period = 1*1000;
        uloop_timeout_set (&send_multi_timer, g_timer_period);
        */

		DEBUG("get tmp_param:%s\n", tmp_param);
		//一次快速打印，然后又恢复10s周期
    	g_timer_period = 1;
    	uloop_timeout_set (&send_multi_timer, g_timer_period);
    	g_timer_period = 10 * 1000;
    	uloop_timeout_set (&send_multi_timer, g_timer_period);
    	ubus_send_reply(ctx, req, rg_wds_ubus_b.head);
    } else {
        DEBUG("rg_wds_ubus_get_info_methods param:NULL\n");
    }
    blob_buf_init(&rg_wds_ubus_b, 0);
    ubus_send_reply(ctx, req, rg_wds_ubus_b.head);
    DEBUG("ubus call suc.");
    return 0;
}
static void rg_wds_send_multi_timer(void);
pthread_mutex_t send_cb_mutex;
/* sta 设置信息方法 */
static int rg_wds_ubus_set_info_methods(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
    struct blob_attr *tb[RG_WDS_UBUS_SET_MAX];
    int update_time;

    DEBUG("rg_wds_ubus_set_info_methods\n");
    blobmsg_parse(rg_wds_ubus_set_policy, ARRAY_SIZE(rg_wds_ubus_set_policy), tb, blob_data(msg), blob_len(msg));
    if (tb[RG_WDS_UBUS_SET_LOG_UPDATE_PERIOD]) {
        update_time = blobmsg_get_u32 (tb[RG_WDS_UBUS_SET_LOG_UPDATE_PERIOD]);
        blobmsg_buf_init(&rg_wds_ubus_b);
	 	DEBUG("update_time:%d",update_time);
		if (update_time){
			DEBUG("set update_time\n");

        	pthread_mutex_lock(&send_cb_mutex);
        	uloop_timeout_set (&send_multi_timer, 0);
			pthread_mutex_unlock(&send_cb_mutex);

        	ubus_send_reply(ctx, req, rg_wds_ubus_b.head);
		}

    } else {
		DEBUG("tb is null\n")
	}
    return 0;
}

/*  sta的ubus连接 */
static void rg_wds_ubus_object_connect (struct uloop_timeout *uloop_t)
{
    int ret;
    const char *ubus_socket = NULL;

    DEBUG("Run in function rg_wds_ubus_object_connect!\n");
    /* 入参检查 */
    if (uloop_t == NULL) {
        DEBUG("The parameter error.");
        return;
    }

    rg_wds_ubus_ctx = ubus_connect(ubus_socket);
    if (!rg_wds_ubus_ctx) {
        uloop_t->cb = rg_wds_ubus_object_connect;
        uloop_timeout_set (uloop_t, RG_WDS_UBUS_CONN_TIMEOUT_S*1000);
        return;
    }

    ubus_add_uloop(rg_wds_ubus_ctx);
    ret = ubus_add_object (rg_wds_ubus_ctx, &rg_wds_ubus_object);
    if (ret != 0) {
        DEBUG("add object fail!");
    }else{
		DEBUG("success!");
	}
	//ubus_add_fd();

    return;
}

/* sta的ubus初始化 */
void rg_wds_ubus_object_init (void)
{
    rg_wds_ubus_object_connect (&rg_wds_ubus_connect_timer);
}



static void rg_wds_send_multi_timer(void)
{

    rg_wds_send_multi();
	pthread_mutex_lock(&send_cb_mutex);
    send_multi_timer.cb = rg_wds_send_multi_timer;
    uloop_timeout_set (&send_multi_timer, g_timer_period);
	pthread_mutex_unlock(&send_cb_mutex);

    return;
}

static void rg_wds_all_proc_timer(void)
{
    rg_wds_all_proc_run();
    time_count_all++;
    wds_all_proc_timer.cb = rg_wds_all_proc_timer;
    uloop_timeout_set (&wds_all_proc_timer, 100);
    return;
}

void rg_wds_all_uloop_timer(void)
{
    (void)rg_wds_all_proc_timer();
}

/**閿涘牐瀚抽弬鍥风礆
 * rg_wds_allnet_info_uloop_timer: 閸忋劎缍夋穱鈩冧紖鐎规碍妞傞崳?+ * @param: void
 * return: void
 *
 * func description: 閿涘牊婀佹禒鈧稊鍫礆閸栧懏瀚崗銊х秹娣団剝浼呴懓浣稿閵嗕焦娲块弬甯礉娴犮儱寮锋穱鈩冧紖閸欐垿鈧胶鐡戦敍娑崇礄閺勵垯绮堟稊鍫礆閸忔湹鑵戦弴瀛樻煀閻ㄥ嫬鍞寸�圭懓瀵橀幏?+ * 閸忋劎缍夐幍鈧張澶変繆閹?tmp/wds_info_all.json閸滃瞼鐣濋崠鏍︿繆閹?tmp/wds_info_lite.json閿涙冻绱欐担婊呮暏閿涘鏁ゆ禍搴ㄥ仸鐏炲懎褰傞柅浣虹秹濡椼儲澧嶉張澶庮啎婢?+ * 閿涘苯鑻熺仦鏇犮仛鐎电懓绨查惃鍕夐幒銉уЦ閸愮绱? */
void rg_wds_allnet_info_uloop_timer(void)
{

    (void)rg_wds_send_multi_timer();
}
