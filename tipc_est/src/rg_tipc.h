#include <linux/version.h>
#include <sys/types.h>
#include <linux/types.h>
#include <ctype.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <time.h>
#include <stdio.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,14)
#include <linux/sysinfo.h>
#else
#include <sys/sysinfo.h>
#endif
#include <time.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <uci.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <linux/wireless.h>
#include <err.h>
#include <netinet/udp.h>
#include <signal.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include "tipc.h"
#include "tipc_list.h"

#define SERVER_TYPE             100
#define SERVER_TYPE_PING        101
#define SERVER_TYPE_UPGRADE     102
#define SERVER_TYPE_DOWNLOAD    103

#define SUCESS              0
#define FAIL                -1
#define TIPC_PEERSN_LEN     16
#define BUF_SIZE_PING       100
#define BUF_SIZE            5000
#define SIZE                3000
#define MAX_SN_NUM          200
#define SN_LENGTH           14
#define MAX_DELAY           10000

#define UPGRADE_MAX_CNT     (3 - 1)
#define UPGRADE_VER_LEN     8
#define UPGRADE_AGE_TIME    260

#define TIPC_QUEUE_MAXCNT   (UPGRADE_MAX_CNT + 1)
#define TIPC_TYPE_DATA      0x01
#define TIPC_TYPE_CTRL      0x02

#define UPGRADE_REQ_CMD         "upgrade_req"
#define UPGRADE_HS2_CMD         "upgrade_hs2"
#define UPGRADE_HS3_CMD         "upgrade_hs3"
#define UPGRADE_HS4_CMD         "upgrade_hs4"
#define TIPC_RMT_TAR_SOFTVER    "cd /tmp/ && tar -ztf \"%s\" | grep version"
#define TIPC_DOWNLOAD_MONITOR   "ps -w|grep -w tipc_download_monitor|grep -v grep|wc -l"
#define TIPC_CLI_DOWNLOAD_PROC  "ps | grep rg_tipc_client_download | grep -v grep"
#define TIPC_TMP_SOFTVERSION    "/tmp/firmware.img"
#define RM_TMP_VERSION          "rm -rf /tmp/firmware.img"
#define DEVSTA_GET_WDS_LIST     "dev_sta get -m wds_list"
// #define GET_WDS_LIST_ALL        "cat /tmp/wds_info_all.json"
#define GET_WDS_LIST_ALL        "dev_sta get -m wds_list_all"
#define GET_TMP_SOFTVERSION     "ls /tmp | grep firmware.img"
#define TIPC_LOCAL_TAR_SOFTVER  "cd /tmp/ && tar -ztf %s | grep version"
#define TIPC_MD5_CMD            "cd /tmp/ && md5sum %s|awk -F ' ' '{print $1}'"
#define TIPC_UPGRD_FINI_STR     "@zhangyz$&"
#define TIPC_DL_MONITOR_SH      "tipc_download_monitor.sh &"
#define TIPC_DOWNLOAD_DIR       "/tmp/tipc_download/"
//#define TIPC_GET_SOFTVER_FROM_PID "cd /tmp/ && tar -zxf firmware.img && cat /tmp/AP_3.0*.support_pids|awk -F ',' '{for(n=1;n<=NF;n++){print $n}}'|awk -F '::' '{print $1}'| uniq | tr \"\n\" \";\" | sed 's/.$//'"
#define TIPC_GET_SOFTVER_FROM_PID "cd /tmp/ && tmp_file=$(tar -ztf firmware.img | grep -F .support_pids) && tar -zxf firmware.img $tmp_file && cat /tmp/AP_3.0*.support_pids|awk -F ',' '{for(n=1;n<=NF;n++){print $n}}'|awk -F '::' '{print $1}'| uniq | tr \"\n\" \";\" | sed 's/.$//'"
#define TIPC_REMOVE_TAR_FILE      "rm -rf /tmp/AP_3.0*"
#define UPGRADE_CLEAR_CACHE		"echo 3 > /proc/sys/vm/drop_caches"

int g_tipc_upgrd_cnt;
bool g_tipc_cond_flag;
int g_all_net_upgrade;
extern int debug;
int lisfd;
char msg[SIZE];
struct sockaddr_in myaddr;

#define TIPC_DEBUG(fmt,args...) {                               \
    if (debug == 1) {                                           \
        printf("[%s][%d]"#fmt"\n",__func__,__LINE__,##args);    \
    }                                                           \
}

typedef struct tipc_upgrade_node_s {
    struct list_head list;
    unsigned char   peersn[TIPC_PEERSN_LEN];    /* upgrade peer serial number */
    bool            flag;                       /* update flag: 1-handshake suc, 0-handshake err */
    unsigned long   time_out;
    bool            hs2_flag;
} tipc_upgrade_node_t;

typedef struct tipc_dl_info_s {
    int     socket_fd;
    char    buf[1500];
} tipc_dl_info_t;

void *rg_tipc_malloc(size_t size);
int sock_bind(int lisfd, int port);
int rg_tipc_udp_recv_init();
int wait_for_msg(int sd);
char *rg_tipc_strdup(char *ptr);
void rg_sn_to_mac(char *sn,char *mac);
void rg_mac_to_softver(char *mac,char *softver);
char *rg_tipc_execute_buf(const char *fmt, ...);
unsigned char *rg_filter_ver_to_int(char *version);
void rg_tipc_thr_hndshk(unsigned char *upgrd_cmd,        unsigned char *ntv_sn);
int rg_tipc_thr_hndshk_and_upgrd(unsigned char *upgrd_cmd,
                                            unsigned char *ntv_sn,
                                            unsigned char *version);
int rg_tipc_message_process(struct sockaddr_in peeraddr);
int rg_tipc_del_all_node_func(void);
void rg_tipc_allnet_sync_upgrd_func(unsigned char *upgrade_cmd, char up_sn[][SN_LENGTH]);
int wait_for_server(__u32 name_type, __u32 name_instance, int wait);
bool rg_version_sync_check(char *upgrd_ver, char *peer_ver);
int rg_tipc_check_download_version(unsigned char *version_name);
int rg_tipc_client_download_targz(unsigned char *trans_sn,
                                             unsigned char *peer_sn,
                                             unsigned char *upgrade_cmd);
int rg_tipc_get_upgrade_bin(unsigned char *sn, unsigned char *version_name);
int rg_tipc_check_upgrd_status(void);
int rg_tipc_create_dl_dir(void);
int rg_tipc_mv_upgrd_file(unsigned char *version_name);
int rg_tipc_local_upgrd_prepare(unsigned char *version_name);
void rg_tipc_client_upgrade_func(unsigned char *trans_sn, unsigned char *peer_sn,
                                                                unsigned char *upgrade_cmd);
unsigned char *rg_tipc_strrpc(unsigned char *str, int len, char *oldstr, char *newstr);
int rg_filter_softversion_devtype(unsigned char *softversion, unsigned char *dev_type,
                                                            unsigned char *version_name);
void rg_tipc_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock);
int rg_tipc_send_process(unsigned char *upgrade_cmd,
                                 unsigned char *native_sn,
                                 unsigned char *version_name);
int rg_tipc_client_socket_link(struct list_head *pos,
                                         unsigned char *upgrade_cmd,
                                         unsigned char *native_sn,
                                         unsigned char *version_name);
void *rg_tipc_file_download_process(void *param);
void *rg_tipc_recv_vergrd_process();
int rg_tipc_server_download_process(void);
void *rg_tipc_mbr_age_process();

