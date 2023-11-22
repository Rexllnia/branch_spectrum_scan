/* spctrm_scn24_ubus.h*/
#ifndef _SPCTRM_SCN24_UBUS_H_
#define _SPCTRM_SCN24_UBUS_H_

/* 
 ubus call spctrm_scn24 set '{"band":5}'
 ubus call spctrm_scn24 set '{"band":2}'

**/

/* ubus call spctrm_scn24 set '{"band":5,"channel_list":[36,40,44,48]}' */
/* cat /etc/spectrum_scan/spctrm_scn24_device_info.json */
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include "libubus.h"
#include "spctrm_scn24_wireless.h"
#include "spctrm_scn24_dev.h"
#include "spctrm_scn24_tipc.h"
#include "spctrm_scn24_config.h"

#define MAX_CHANNEL_NUM 200 
#define UBUS_DEFER_REQUEST
enum {
    SPCTRM_SCN_BAND,
    SPCTRM_SCN_CHANNEL_LIST,
    SPCTRM_SCN_SCAN_TIME,
    __SPCTRM_SCN_SCAN_MAX
};


struct spctrm_scn24_ubus_set_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    unsigned long int channel_bitmap[2];
    uint8_t bw_bitmap;
    unsigned long int channel_num;
    uint8_t scan_time;
    uint8_t band;
    struct spctrm_scn24_device_info spctrm_scn24_device_info;
    int fd;
    int idx;
    int channel_index;
    int spctrm_scn24_tipc_wait_cpe_retry;
};

void spctrm_scn24_ubus_task(struct ubus_context *ctx);
int spctrm_scn24_ubus_add_blobmsg(struct blob_buf *buf,struct spctrm_scn24_device_list *spctrm_scn24_device_list,struct spctrm_scn24_ubus_set_request *hreq);
#endif
