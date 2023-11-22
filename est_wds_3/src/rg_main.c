#include<sys/resource.h>
#include "rg_wds.h"
#define DCONFIG_WDS_CORE_DUBUG 1
int gpio_id;    //debug模块id
extern pthread_mutex_t mtx_rg_wds_all_info;
extern pthread_cond_t cond_rg_wds_all_info;
extern pthread_mutex_t rg_wds_crypt_mtx;

int main()
{
    const char *ubus_socket = NULL;
    struct ubus_context *deb_ubus_ctx = NULL;
	pthread_t thread_wds_ringbuffer_recv;
    pthread_t thread_wds_ringbuffer_handle;
    pthread_t thread_wds_broadcast_send;
	pthread_t thread_wds_receve_beacon;
	pthread_t thread_wds_get_udp_message;
#ifdef EST_SUPPORT_REDIS
    pthread_t thread_wds_redis_sub;
#endif
    
#ifdef DCONFIG_WDS_CORE_DUBUG
	struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
	printf("add core dump\n");
#endif

    uloop_init();
	(void)dbg_init("wds_gpio", GPIO_DBG_FILE, 10);
    gpio_id = dbg_module_reg("gpio");
    deb_ubus_ctx = ubus_connect(ubus_socket);
    ubus_add_uloop(deb_ubus_ctx);
    ubus_add_object(deb_ubus_ctx, dbg_get_ubus_object());

    //Read device capability table
    if (FAIL == dev_capacity_init(&rg_dev_capacity_table))
    {
        GPIO_ERROR("Device capacity table get fail!");
        return FAIL;
    }
    
	rg_wds_dev_init(&rg_dev_info_t);
	rg_wds_ath_init(&rg_dev_info_t,&rg_ath_info_t);
	//设备端适配，有301 302,301/2.0
	rg_wds_dev_match();

	//LED的同步处理函数，后台使用定时器
	//rg_wds_led_timer();

    pthread_mutex_init(&mtx_rg_wds_all_info, NULL);
    pthread_cond_init(&cond_rg_wds_all_info, NULL);
    pthread_mutex_init(&rg_wds_crypt_mtx, NULL);

    RingBuffer ringbuf;
    ringbuffer_init(&ringbuf);

    thread_pool pool;
    thread_pool_init(&pool);

    thread_args args;
    args.ringbuf = &ringbuf;
    args.pool = &pool;
    
#ifdef EST_SUPPORT_REDIS
    /* redis数据库初始化和消息订阅 */
    GPIO_ERROR("rg_wds_redis_sub_thread start!");
	if (0 != pthread_create(&thread_wds_redis_sub,NULL,rg_wds_redis_sub_thread,NULL)) 
    {
		GPIO_ERROR("Create thread_wds_redis_sub fail!");
	}
    system("redis-cli -p 6380 flushall");
#endif

	//UDP broadcast 50003 type packet push to ringbuffer
	if (0 != pthread_create(&thread_wds_ringbuffer_recv,NULL,ringbuffer_pkt_recv_pthread,&ringbuf)) 
    {
		GPIO_ERROR("Create thread_wds_receve_date fail!");
	}

    //UDP broadcast 50003 type packet handle
	if (0 != pthread_create(&thread_wds_ringbuffer_handle,NULL,ringbuffer_pkt_handle_pthread,&args)) 
    {
		GPIO_ERROR("Create rg_wds_udp_packet_handle_pthread fail!");
	}

    //UDP broadcast packet send and status check
	if (0 != pthread_create(&thread_wds_broadcast_send,NULL,broadcast_pkt_send_pthread,NULL)) 
    {
		GPIO_ERROR("Create broadcast_pkt_send_pthread fail!");
	}

	//获取SSID信息
	if (0 != pthread_create(&thread_wds_receve_beacon,NULL,rg_wds_beacon_pthread,NULL))
    {
		GPIO_ERROR("Create thread_wds_receve_beacon fail!");
	}
	
	//升级，tipc通信
	if (0 != pthread_create(&thread_wds_get_udp_message,NULL,rg_wds_udp_process,NULL))
    {
		GPIO_ERROR("Create thread_wds_get_udp_message fail!");
	}
    GPIO_DEBUG("dev_multi_info sizeof %d",sizeof(struct dev_multi_info));

    wds_gpio_run();

    uloop_run();
    uloop_done();
}
