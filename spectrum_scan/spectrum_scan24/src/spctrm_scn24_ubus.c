/*
 * Copyright (C) 2011-2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "spctrm_scn24_ubus.h"

static int spctrm_scn24_ubus_set(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
static int spctrm_scn24_ubus_get(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
              
struct spctrm_scn24_ubus_get_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    int fd;
    int idx;
    char data[];
};

extern char g_2g_ext_ifname[IFNAMSIZ];
extern char g_5g_ext_ifname[IFNAMSIZ];
static struct ubus_connect_ctx *g_ctx;
struct spctrm_scn24_device_list g_spctrm_scn24_device_list;
int8_t g_spctrm_scn24_status;
uint8_t g_spctrm_scn24_scan_schedual;

static const struct blobmsg_policy spctrm_scn24_ubus_set_policy[] = {
    [SPCTRM_SCN_BAND] = {.name = "band", .type = BLOBMSG_TYPE_INT32},
    [SPCTRM_SCN_CHANNEL_LIST] = {.name = "channel_list", .type = BLOBMSG_TYPE_ARRAY},
    [SPCTRM_SCN_SCAN_TIME] = {.name = "scan_time", .type = BLOBMSG_TYPE_INT32},
};
static const struct ubus_method spctrm_scn24_methods[] = {
    UBUS_METHOD_NOARG("get", spctrm_scn24_ubus_get),
    UBUS_METHOD("set", spctrm_scn24_ubus_set, spctrm_scn24_ubus_set_policy),
};
static struct ubus_object_type spctrm_scn24_object_type =
    UBUS_OBJECT_TYPE("spctrm_scn24", spctrm_scn24_methods);

static struct ubus_object spctrm_scn24_object = {
    .name = "spctrm_scn24",
    .type = &spctrm_scn24_object_type,
    .methods = spctrm_scn24_methods,
    .n_methods = ARRAY_SIZE(spctrm_scn24_methods),
};

static void add_score_list_blobmsg(struct blob_buf *buf, unsigned long int *channel_bitmap, struct spctrm_scn24_channel_info *channel_info_list,int band)
{
    int bit;
    uint8_t channel;
    char temp[128];
    void *const score_list = blobmsg_open_array(buf, "score_list");
    void *score_list_elem;
    bit = 0;
    debug("floornoise %d \r\n",channel_info_list[1].floornoise);
    for_each_set_bit(bit,channel_bitmap,CHANNEL_BITMAP_SIZE) {
        score_list_elem = blobmsg_open_table(buf,"");

        if (bitset_to_channel(bit,&channel,band) == FAIL) {
            debug("FAIL");
            return;
        }

        sprintf(temp,"%d",channel);
        blobmsg_add_string(buf,"channel",temp);
        sprintf(temp,"%f",channel_info_list[bit].score);
        blobmsg_add_string(buf,"score",temp);
        blobmsg_close_table(buf,score_list_elem);
    }

    blobmsg_close_array(buf, score_list);
}

static void add_bw40_blobmsg(struct blob_buf *buf, struct spctrm_scn24_device_info *device,struct spctrm_scn24_ubus_set_request *hreq)
{
    void *const bw40_table = blobmsg_open_table(buf, "bw_40");
    char temp[128];
    unsigned long int bw40_bitmap[2];
    if (hreq->band == BAND_5G) {
        spctrm_scn24_wireless_get_bw40_bitmap(hreq->channel_bitmap,bw40_bitmap);
        add_score_list_blobmsg(buf,bw40_bitmap,device->bw40_channel_info,hreq->band);
        debug("%f\r\n",device->bw40_channel_info[0].score);
    }
    blobmsg_close_table(buf, bw40_table);
}

static void add_bw20_blobmsg(struct blob_buf *buf, struct spctrm_scn24_device_info *device,struct spctrm_scn24_ubus_set_request *hreq)
{
    void *const bw20_table = blobmsg_open_table(buf, "bw_20");
    int i,channel;

    if (buf == NULL || device == NULL || hreq == NULL) {
        debug("FAIL");
        return ;
    } 
    debug("device->bw20_channel_info->channel %d\r\n",device->bw20_channel_info[1].channel);
    debug("device->bw20_channel_info->floornoise %d\r\n",device->bw20_channel_info[1].floornoise);
    debug("hreq->channel_num %d\r\n",hreq->channel_num);
    add_score_list_blobmsg(buf,hreq->channel_bitmap,device->bw20_channel_info,hreq->band);
    blobmsg_close_table(buf, bw20_table);
}
static void add_device_info_blobmsg(struct blob_buf *buf, struct spctrm_scn24_device_info *device,struct spctrm_scn24_ubus_set_request *hreq)
{
    void *const device_obj = blobmsg_open_table(buf, NULL);
    void *BAND_obj;

    blobmsg_add_string(buf, "SN", device->series_no);
    blobmsg_add_string(buf, "role", device->role);

    /* 5G */
    if (hreq->band == BAND_5G) {
        BAND_obj = blobmsg_open_table(buf, "5G");
    } else {
        BAND_obj = blobmsg_open_table(buf, "2G");
    }
 
    add_bw40_blobmsg(buf, device,hreq);
    debug("add bw40\r\n");
    add_bw80_blobmsg(buf, device,hreq);
    debug("add bw80\r\n");


    blobmsg_close_table(buf, BAND_obj);
    blobmsg_close_table(buf, device_obj);
}

static void add_timestamp_blobmsg(struct blob_buf *buf, time_t *timestamp)
{
    char temp[256];   
    sprintf(temp, "%ld", *timestamp);
    blobmsg_add_string(buf, "timestamp", temp);
}

static inline void average_init(double *avg)
{
    *avg = 0;
}
static inline void average_add(double *avg,double val,double weight) 
{
    *avg += val * weight;
}

static void add_avg_score_list_blobmsg(struct blob_buf *buf,
                struct spctrm_scn24_ubus_set_request *hreq,
                struct spctrm_scn24_device_list *list) 
{
    struct spctrm_scn24_device_info *p;
    void *avg_score_list,*avg_score_list_elem;
    int channel;
    int i,bit;
    double avg_score = 0;
    char tmp[128];

    bit = 0;
    channel = 0;
    avg_score_list = blobmsg_open_array(buf,"avg_score_list");

    for_each_set_bit(bit,hreq->channel_bitmap,CHANNEL_BITMAP_SIZE) {
        average_init(&avg_score);
        list_for_each_device(p,i,list) {
            average_add(&avg_score,p->bw20_channel_info[bit].score,1.0/g_spctrm_scn24_device_list.list_len);
        }
        avg_score_list_elem = blobmsg_open_table(buf,"");
        bitset_to_channel(bit,&channel,hreq->band);
        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%d",channel);
        blobmsg_add_string(buf,"channel",tmp);
        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%f",avg_score);
        blobmsg_add_string(buf,"avg_score",tmp);
        blobmsg_close_table(buf,avg_score_list_elem);
    }

    blobmsg_close_array(buf,avg_score_list);
    
}

static void add_bw40_best_channel_blobmsg(struct blob_buf *buf, struct spctrm_scn24_device_list *list)
{
    void *const bw40_table = blobmsg_open_table(buf, "bw_40");

    blobmsg_close_table(buf, bw40_table);
}

int spctrm_scn24_ubus_add_blobmsg(struct blob_buf *buf,struct spctrm_scn24_device_list *spctrm_scn24_device_list,struct spctrm_scn24_ubus_set_request *hreq)
{
    struct spctrm_scn24_device_info *p;
    int i;
    void *scan_list;
    void *scan_list_elem;

    if (buf == NULL || spctrm_scn24_device_list == NULL || hreq == NULL) {
        return FAIL;
    }
    
    debug("\r\n");
    scan_list = blobmsg_open_array(buf,"scan_list");
    if (scan_list == NULL) {
        debug("FAIL\r\n");
        return;
    }
    list_for_each_device(p,i,spctrm_scn24_device_list) {
        scan_list_elem = blobmsg_open_table(buf,"");  
        debug("series_no %s\r\n",p->series_no); 
        debug("role %s\r\n",p->role); 
        debug("floornoise %d\r\n",p->bw20_channel_info[1].floornoise);
        blobmsg_add_string(buf, "SN", p->series_no);
        blobmsg_add_string(buf, "role", p->role);
        add_bw20_blobmsg(buf,p,hreq);
        add_bw40_blobmsg(buf,p,hreq);
        blobmsg_close_table(buf,scan_list_elem);
    }
    blobmsg_close_array(buf,scan_list);
    add_avg_score_list_blobmsg(buf,hreq,spctrm_scn24_device_list);

    return SUCCESS;
}


static void spctrm_scn24_tipc_wait_cpe_cb(struct uloop_timeout *t) 
{
    struct spctrm_scn24_ubus_set_request *hreq = container_of(t,struct spctrm_scn24_ubus_set_request,timeout);
    struct spctrm_scn24_device_info *p;
    int i;

    debug("band %d\r\n",hreq->band);
    hreq->spctrm_scn24_tipc_wait_cpe_retry++;
    if (hreq->spctrm_scn24_tipc_wait_cpe_retry == 10) {
        goto scan_start;
    }
    
    list_for_each_device(p,i,&g_spctrm_scn24_device_list) {
        debug("wait device %s \r\n",p->series_no);
        if (p->finished_flag != FINISHED) {
            debug("retry\r\n");
            uloop_timeout_set(&hreq->timeout,500);
            return;
        }
    }

scan_start:
    spctrm_scn24_dev_reset_stat(&g_spctrm_scn24_device_list);
    list_for_each_device(p,i,&g_spctrm_scn24_device_list) {
        debug("p->finished_flag %d \r\n",p->finished_flag);
    }
    hreq->channel_index = 0;
    hreq->channel_index = find_first_bit(hreq->channel_bitmap,CHANNEL_BITMAP_SIZE);
    hreq->timeout.cb = spctrm_scn24_wireless_scan_task;
    uloop_timeout_set(&hreq->timeout,1000);
    debug("\r\n");
    return;
}

static void spctrm_scn24_ubus_set_reply(struct uloop_timeout *t) 
{ 
    char start_msg[9] = "start";
    struct spctrm_scn24_channel_info current_channel_info;
    struct spctrm_scn24_ubus_set_request *hreq = container_of(t,struct spctrm_scn24_ubus_set_request,timeout);
    int i;
    struct spctrm_scn24_device_info *p;
    char *payload;
    static struct blob_buf buf;
    __u32 instant;

    debug("\r\n");
    instant = 0;
    debug("band %d\r\n",hreq->band);
    debug("band %d\r\n",hreq->band);

    // blob_buf_init(&buf,0);
    // blobmsg_add_string(&buf,"tes","qweqwe");
    // ubus_send_reply(g_ctx,&hreq->req,buf.head);
    // ubus_complete_deferred_request(g_ctx,&hreq->req,0);

    list_for_each_device(p,i,&g_spctrm_scn24_device_list) {
        if (strcmp(p->role,"ap") != 0) {
            if (spctrm_scn24_common_mac_2_nodeadd(p->mac,&instant) == FAIL) {
                debug("FAIL\r\n");
                free(hreq);
                g_spctrm_scn24_status = SPCTRM_SCN24_SCAN_ERROR;
                spctrm_scn24_dev_ap_status_to_file(g_spctrm_scn24_status);
                
                return;
            }

            debug("send to mac %x\r\n",p->mac);
            debug("%d\r\n",hreq->scan_time);
            spctrm_scn24_tipc_send(instant,PROTOCAL_TYPE_SCAN,sizeof(struct spctrm_scn24_ubus_set_request),hreq);
        }	
    }

    debug("\r\n");

    memset(&current_channel_info,0,sizeof(current_channel_info));
    if (spctrm_scn24_wireless_get_channel_info(&current_channel_info,GET_EXT_IFNAME(hreq->band)) == FAIL) {
        debug("FAIL");
        spctrm_scn24_wireless_error_handle(t);
        return;
    }
    if (hreq->band == BAND_5G) {
        spctrm_scn24_wireless_channel_info_to_file(&current_channel_info,"saved_channel_info_5g","/etc/spectrum_scan/saved_channel_info.json");
    } else if (hreq->band == BAND_2G) {
        spctrm_scn24_wireless_channel_info_to_file(&current_channel_info,"saved_channel_info_2g","/etc/spectrum_scan/saved_channel_info.json");
    }
    
    /* xxx 切频宽 */
    spctrm_scn24_wireless_change_bw(_20MHZ,hreq->band); 
    debug("band %d\r\n",hreq->band);

    p = spctrm_scn24_dev_find_ap(&g_spctrm_scn24_device_list);
    p->finished_flag = FINISHED;
    hreq->timeout.cb = spctrm_scn24_tipc_wait_cpe_cb;
    uloop_timeout_set(&hreq->timeout,1000);
}


static int spctrm_scn24_ubus_set(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
    struct spctrm_scn24_ubus_set_request *hreq;
    size_t len;
    static struct blob_buf buf;
    struct blob_attr *tb[__SPCTRM_SCN_SCAN_MAX];
    struct blob_attr *channel_list_array[MAX_CHANNEL_NUM];
    static struct blobmsg_policy channel_list_policy[MAX_CHANNEL_NUM];
    int i;
    unsigned long country_channel_bitmap[2];
    uint8_t band,channel_num,channel,nr;
    struct spctrm_scn24_device_info *p;

    blob_buf_init(&buf, 0);

    for (i = 0; i < MAX_CHANNEL_NUM; i++) {
        channel_list_policy[i].type = BLOBMSG_TYPE_INT32;
    }

    blobmsg_parse(spctrm_scn24_ubus_set_policy, ARRAY_SIZE(spctrm_scn24_ubus_set_policy), tb, blob_data(msg), blob_len(msg));

    if (g_spctrm_scn24_status == SPCTRM_SCN24_SCAN_BUSY) {
        goto error;
    }

    if (tb[SPCTRM_SCN_BAND]) {
        band = blobmsg_get_u32(tb[SPCTRM_SCN_BAND]);
        debug("band %d\r\n",band);
    } else {
        debug("band NULL\r\n");
        goto error;
    }

    if (band != BAND_5G && band != BAND_2G) {
        debug("band error\r\n");
        goto error;
    }

    memset(country_channel_bitmap,0,sizeof(country_channel_bitmap));
    if (spctrm_scn24_wireless_country_channel_get_channellist(country_channel_bitmap,&channel_num,SPCTRM_SCN24_BW_20,band) == FAIL) {
        debug("fail\r\n");
        goto error;
    }

    len = sizeof(struct spctrm_scn24_ubus_set_request);
	hreq = calloc(1, len);
    memset(&hreq->bw_bitmap,0,sizeof(uint8_t));
    memset(hreq->channel_bitmap,0,sizeof(hreq->channel_bitmap));
    hreq->channel_index = 0;
    hreq->channel_num = 0;
    hreq->scan_time = 0;
    hreq->band = 0;
    memset(&hreq->spctrm_scn24_device_info,0,sizeof(struct spctrm_scn24_device_info));
    if (hreq == NULL) {
        debug("fail\r\n");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    hreq->band = band;
    debug("band %d\r\n",hreq->band);
    if (spctrm_scn24_wireless_country_channel_get_bwlist(&hreq->bw_bitmap,hreq->band) == FAIL) {
        goto error;
    }
    debug("band %d\r\n",hreq->band);
    if (tb[SPCTRM_SCN_CHANNEL_LIST]) {
        /* custom channel list */
        channel_num = blobmsg_check_array(tb[SPCTRM_SCN_CHANNEL_LIST], BLOBMSG_TYPE_INT32);
        blobmsg_parse_array(channel_list_policy, ARRAY_SIZE(channel_list_policy), channel_list_array, blobmsg_data(tb[SPCTRM_SCN_CHANNEL_LIST]), blobmsg_len(tb[SPCTRM_SCN_CHANNEL_LIST]));
        for (i = 0;i < channel_num;i++) {
            channel = blobmsg_get_u32(channel_list_array[i]);

            if (spctrm_scn24_wireless_check_channel(channel) == FAIL) {
                debug("fail\r\n");
                free(hreq);
                g_spctrm_scn24_status = SPCTRM_SCN24_SCAN_ERROR;
                spctrm_scn24_dev_ap_status_to_file(g_spctrm_scn24_status);
                goto error;
            }
            debug("band %d",hreq->band);
            if (channel_to_bitset(channel,&nr,hreq->band) == FAIL) {
                debug("fail\r\n");
                free(hreq);
                g_spctrm_scn24_status = SPCTRM_SCN24_SCAN_ERROR;
                spctrm_scn24_dev_ap_status_to_file(g_spctrm_scn24_status);
                goto error;
            }

            set_bit(nr,hreq->channel_bitmap);            
        }
        spctrm_scn24_wireless_show_channel_bitmap(hreq->channel_bitmap);
    
    } else {
        /* default */
        debug("band %d\r\n",hreq->band);
        memcpy(hreq->channel_bitmap,country_channel_bitmap,sizeof(country_channel_bitmap));
        spctrm_scn24_wireless_show_channel_bitmap(hreq->channel_bitmap);
        debug("band %d\r\n",hreq->band);
    }
    debug("band %d\r\n",hreq->band);
    spctrm_scn24_wireless_show_channel_bitmap(hreq->channel_bitmap);
    debug("band %d\r\n",hreq->band);
    if (tb[SPCTRM_SCN_SCAN_TIME]) {
        hreq->scan_time = blobmsg_get_u32(tb[SPCTRM_SCN_SCAN_TIME]);
    } else {
        /* default */
        hreq->scan_time = DEFAULT_SCAN_TIME;
    }
    debug("--------------------bitmap set-----------------\r\n");
    spctrm_scn24_wireless_show_channel_bitmap(hreq->channel_bitmap);
    debug("-----------------------------------------------\r\n");

    if (spctrm_scn24_dev_wds_list(&g_spctrm_scn24_device_list) == FAIL) {
        debug("fail");
        free(hreq);
        g_spctrm_scn24_status = SPCTRM_SCN24_SCAN_ERROR;
        spctrm_scn24_dev_ap_status_to_file(g_spctrm_scn24_status);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    debug("--------------------bitmap set-----------------\r\n");
    spctrm_scn24_wireless_show_channel_bitmap(hreq->channel_bitmap);
    debug("-----------------------------------------------\r\n");

    debug("band %d\r\n",hreq->band);
    p = spctrm_scn24_dev_find_ap(&g_spctrm_scn24_device_list);
    if (p == NULL) {
        debug("fail");
        free(hreq);
        g_spctrm_scn24_status = SPCTRM_SCN24_SCAN_ERROR;
        spctrm_scn24_dev_ap_status_to_file(g_spctrm_scn24_status);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    debug("band %d\r\n",hreq->band);
    debug("--------------------bitmap set-----------------\r\n");
    spctrm_scn24_wireless_show_channel_bitmap(hreq->channel_bitmap);
    debug("-----------------------------------------------\r\n");
    
    hreq->channel_num = channel_num;
    memcpy(&hreq->spctrm_scn24_device_info,p,sizeof(struct spctrm_scn24_device_info));
    g_spctrm_scn24_status = SPCTRM_SCN24_SCAN_BUSY;
    debug("band %d\r\n",hreq->band);
    spctrm_scn24_dev_ap_status_to_file(g_spctrm_scn24_status);
    debug("band %d\r\n",hreq->band);
    debug("status save success\r\n");
    
    // ubus_defer_request(ctx,req,&hreq->req);

    hreq->timeout.cb = spctrm_scn24_ubus_set_reply;
    uloop_timeout_set(&hreq->timeout,1000);
    debug("\r\n");

    blobmsg_add_string(&buf,"code","0");
    ubus_send_reply(ctx,req,buf.head);
    return UBUS_STATUS_OK;
error:
    blobmsg_add_string(&buf,"code","-1");
    ubus_send_reply(ctx,req,buf.head);
    return UBUS_STATUS_OK;
}

static int spctrm_scn24_ubus_get(struct ubus_context *ctx, struct ubus_object *obj,
						struct ubus_request_data *req, const char *method,
						struct blob_attr *msg)
{
	struct blob_attr *tb[__SPCTRM_SCN_SCAN_MAX];
    struct spctrm_scn24_ubus_get_request *hreq;
    size_t len;
    static struct blob_buf buf;
    char tmp[128];
    
    len = sizeof(struct spctrm_scn24_ubus_get_request);
	hreq = calloc(1, len);
    if (hreq == NULL) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    blob_buf_init(&buf, 0);
    blobmsg_add_json_from_file(&buf,"/etc/spectrum_scan/spctrm_scn24_device_list.json");
    if (g_spctrm_scn24_status == SPCTRM_SCN24_SCAN_BUSY) {
        sprintf(tmp,"%d",g_spctrm_scn24_scan_schedual);
        blobmsg_add_string(&buf,"scan_schedual",tmp);
    }
    ubus_send_reply(ctx,req,buf.head);

	return UBUS_STATUS_OK;
}

void spctrm_scn24_ubus_task(struct ubus_context *ctx)
{
    const char *ubus_socket = NULL;
    int ret;
    debug("\r\n");
    
    g_ctx = ctx;
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return NULL;
    }

    ret = ubus_add_object(ctx, &spctrm_scn24_object);
    if (ret) {
        fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
        return;
    }

    debug("\r\n");
    ubus_add_uloop(ctx);
    debug("spctrm_scn24_ubus_task\r\n");
}
