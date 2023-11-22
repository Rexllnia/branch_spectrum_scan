/* spctrm_scn24_config.h */
#ifndef _SPCTRM_SCN24_CONFIG_H_
#define _SPCTRM_SCN24_CONFIG_H_

#include "spctrm_scn24_common.h"

#define SN_LEN 14

#define SCAN_INTERVAL 500
#define DEFAULT_SCAN_TIME 5
#define MIN_SCAN_TIME 10 
#define MAX_SCAN_TIME 60
#define EXPIRE_TIME 14

#define ETH_ALEN 6

#define POPEN_BUFFER_MAX_SIZE   8192

#define _20MHZ 20
#define _40MHZ 40
#define _80MHZ 80
 
#define SPCTRM_SCN24_BW_20   1
#define SPCTRM_SCN24_BW_40   (1 << 1)
#define SPCTRM_SCN24_BW_80   (1 << 2)
#define SPCTRM_SCN24_BW_160  (1 << 3) 

#define SPCTRM_SCN24_SCAN_BUSY       1
#define SPCTRM_SCN24_SCAN_IDLE       2
#define SPCTRM_SCN24_SCAN_NOT_START  0
#define SPCTRM_SCN24_SCAN_TIMEOUT  	 3
#define SPCTRM_SCN24_SCAN_ERROR  	-1

#define FAIL       -1
#define SUCCESS    0

#define SPCTRM_SCN24_MAX_DEVICE_NUM 5
#define BAND_5G_MAX_CHANNEL_NUM 36

#define BAND_5G     5
#define BAND_2G     2

#define AP_MODE  0
#define CPE_MODE 1

#define CHANNEL_BITMAP_SIZE 64

uint8_t g_spctrm_scn24_mode;
uint8_t g_band_support;


#define debug(...)  do {\
                    printf("file : %s line: %d func: %s -->",__FILE__,__LINE__,__func__); \
                    printf(__VA_ARGS__);\
} while(0)

struct param_input {
    uint64_t channel_bitmap;
    uint8_t band;
    uint8_t channel_num;
    uint8_t scan_time;
    struct uloop_timeout timeout;
};

struct spctrm_scn24_channel_info {
    uint8_t channel;
    int8_t floornoise;
    uint8_t utilization;
    uint8_t bw;
    uint8_t obss_util;
    uint8_t tx_util;
    uint8_t rx_util;
    double score;
    double rate;
};

#endif
