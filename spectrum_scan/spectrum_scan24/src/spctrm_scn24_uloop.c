#include "spctrm_scn24_uloop.h"

extern __u32 g_spctrm_scn24_ap_instant;
extern int8_t g_spctrm_scn24_status;
extern char g_2g_ext_ifname[IFNAMSIZ];
extern char g_5g_ext_ifname[IFNAMSIZ];
extern uint8_t g_band_support;

static int server_main(struct ubus_context *ctx)
{
    int ret;
    char mac[20];
#ifdef REDBS_ENABLE
    spctrm_scn24_redbs_get_dev_list_info();
#endif

    if (g_spctrm_scn24_mode == AP_MODE) {

    } else if (g_spctrm_scn24_mode == CPE_MODE) {

    }
    if (g_spctrm_scn24_mode == AP_MODE) {
        spctrm_scn24_wireless_restore_pre_status();
        spctrm_scn24_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
        if (spctrm_scn24_common_mac_2_nodeadd(mac,&g_spctrm_scn24_ap_instant) == FAIL) {
            return FAIL;
        }
        spctrm_scn24_ubus_task(ctx);
    }
    
    spctrm_scn24_tipc_task();
    return SUCCESS;
}

int spctrm_scn24_uloop(struct ubus_context *ctx)
{
    int ret;
    FILE *fp;

    if (spctrm_scn24_wireless_get_wds_state(&g_spctrm_scn24_mode) == FAIL) {
        return FAIL;
    }

    spctrm_scn24_wireless_get_ext_ifname(g_5g_ext_ifname,BAND_5G);
    spctrm_scn24_wireless_get_ext_ifname(g_2g_ext_ifname,BAND_2G);

    system("mkdir /tmp/spectrum_scan24");

    fp = fopen("/tmp/spectrum_scan24/curl_pid","w+");
    if (fp == NULL) {
        return FAIL;
    } 
    
    fprintf(fp,"%d",getpid());
    fclose(fp);

    server_main(ctx);



	return 0;
}

void spctrm_scn24_close()
{
    debug("spctrm_scn24 done");
    tipc_close();
    uloop_done();
}




