/* main.h */
#ifndef _MAIN_H_
#define _MAIN_H_

#include "spctrm_scn_wireless.h"
#include <sys/ioctl.h>
#include "was_sdk.h"
#include <linux/wireless.h>

extern unsigned char g_mode;
extern struct device_list g_finished_device_list;
extern struct device_list g_device_list;
struct channel_info g_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
struct channel_info realtime_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern struct user_input g_input;
volatile int g_status,g_scan_time;
volatile time_t g_scan_timestamp;
extern long g_bitmap_2G,g_bitmap_5G;
char g_wds_bss[16];
char g_apcli_ifname[16];

pthread_mutex_t g_mutex,g_scan_schedule_mutex,g_finished_device_list_mutex,g_popen_mutex;

pthread_t pid1, pid2 ,pid3;
sem_t g_semaphore;

#endif