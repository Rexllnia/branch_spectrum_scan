#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/time.h>
#include <linux/timer.h>

#include "rg_wds_beacon.h"

/*netlink attributes 可以通过枚举索引找到对应的类型
*用户空间应用程序要传递这样的信息*/

enum {
DOC_EXMPL_A_UNSPEC,
DOC_EXMPL_A_MSG,
DOC_EXMPL_A_KEYERROR,
__DOC_EXMPL_A_MAX,
};
#define DOC_EXMPL_A_MAX (__DOC_EXMPL_A_MAX - 1)

/*atribute policy就是定义各个属性的具体类型，参见net/netlink.h*/
static struct nla_policy doc_exmpl_genl_policy[DOC_EXMPL_A_MAX + 1] = {
    [DOC_EXMPL_A_MSG] = {.type = NLA_NUL_STRING},
    [DOC_EXMPL_A_KEYERROR] = {.type = NLA_NUL_STRING},
};

#define VERSION_NR 1

//generic netlink family 定义
static struct genl_family doc_exmpl_genl_family = {
    .id = GENL_ID_GENERATE,
    .hdrsize = 0,
    .name = "CONTROL_EXMPL",
    .version = VERSION_NR,
    .maxattr = DOC_EXMPL_A_MAX,
};

/*定义命令类型，用户空间以此来表明需要执行的命令*/
enum{
    DOC_EXMPL_C_UNSPEC,
    DOC_EXMPL_C_ECHO,
	DOC_KEYERROR,
    DOC_FASR_WDS_INFO,
    DOC_CALIBRATE_RSSI,
    __DOC_EXMPL_C_MAX,
};

enum func_mode_ssid_key{
	SCAN_PAIR = 1,
	ONE_CC,
};

#define DOC_EXMPL_C_MAX (__DOC_EXMPL_C_MAX - 1)

int fd;
int lock_status;

struct wds_beacon_info_s {
    char role;
    char wds_connect_status;
    int rssi;
    char wds_ssid[33];
    unsigned char mac[MAC_ADDR_LEN];
    unsigned char sn[14];
	//The following are the new parameters
	unsigned char is_exist_expend;
	struct expand_wds_beacon_info_s expand_info;
};

typedef struct key_error_info_s {
    int   connstate;
	unsigned char ath_mac[MAC_ADDR_LEN];
	unsigned char sn[14];
    unsigned char dev_mac[18];
	unsigned char keyerr_type;
} key_error_info_t;

typedef struct fast_wds_info_s {
	unsigned char app_ssid[MAX_LEN_OF_SSID+1];
	unsigned char app_key[LEN_PSK + 1];
	unsigned char channel;
	unsigned char func_mode;
	unsigned char countrycode[4];
}fast_wds_info_t;

typedef struct {
	unsigned char mac[6];
    char uplink_rssi_h;
    char uplink_rssi_v;
    char downlink_rssi_h;
    char downlink_rssi_v;
}rssi_calib_data_t;

#if defined(ESTBCN_REGISTER_MT7663_CB_SUPPORT) || defined(ESTBCN_REGISTER_MT7628_CB_SUPPORT)
typedef void (*est_wds_send_to_app_func_t)(struct send_to_app_scaninfo *);
typedef struct estwds_send_to_app_cb_s {
    est_wds_send_to_app_func_t pfunc;
} estwds_send_to_app_cb_t;

typedef void (*keyerror_send_to_app_func_t)(unsigned char, int, unsigned char *,unsigned char *, unsigned char *);
typedef struct keyerror_send_to_app_cb_s {
    keyerror_send_to_app_func_t pfunc;
} keyerror_send_to_app_cb_t;

typedef void (*est_fast_wds_info_send_to_app_func_t)(fast_wds_info_t *);
typedef void (* est_rssi_send_to_app_func_t)(rssi_calib_data_t *);

#endif
#ifdef ESTBCN_REGISTER_MT7663_CB_SUPPORT
extern void mt7663_estwds_register_send_to_app_cb(est_wds_send_to_app_func_t func);
extern void mt7663_keyerror_register_send_to_app_cb(keyerror_send_to_app_func_t func);
extern void mt7663_fast_wds_info_register_send_to_app_cb(est_fast_wds_info_send_to_app_func_t func);
extern void mt7663_estrssi_register_send_to_app_cb(est_rssi_send_to_app_func_t func);
#endif

#ifdef ESTBCN_REGISTER_MT7628_CB_SUPPORT
extern void mt7628_estbcn_register_send_to_app_cb(est_wds_send_to_app_func_t func);
extern void mt7628_keyerror_register_send_to_app_cb(keyerror_send_to_app_func_t func);
extern void mt7628_fast_wds_info_register_send_to_app_cb(est_fast_wds_info_send_to_app_func_t func);
#endif

unsigned char g_wdsbcn_ntvsn[WDS_NTV_SN] = {0};  /* store native serial number */

void rj_wdsssid_cp_ntvsn(unsigned char *ntv_sn)
{
    if (!ntv_sn) {
        return;
    }

    strncpy(ntv_sn, g_wdsbcn_ntvsn, sizeof(g_wdsbcn_ntvsn) - 1);
}
EXPORT_SYMBOL(rj_wdsssid_cp_ntvsn);

void send_date_to_app_beacon(struct send_to_app_scaninfo *send_param) {
	//Old parameter:char *ssid,char wds_status,char role,int rssi,const char *mac, unsigned char *sn
    struct nlattr *na;
    struct sk_buff *skb;
    int rc;
    void *msg_hdr;
    char *data;
	int size;
    struct wds_beacon_info_s wds_info;

    if (fd <= 0) {
        return;
    }

    size = nla_total_size(sizeof(struct wds_beacon_info_s));
    skb = genlmsg_new(size,GFP_ATOMIC);
    if(!skb) {
        return;
    }

    msg_hdr = genlmsg_put(skb,0,0,&doc_exmpl_genl_family,0,DOC_EXMPL_C_ECHO);
    if (msg_hdr == NULL) {
        nlmsg_free(skb);
        return;
    }

    //填充具体的netlink attribute:DOC_EXMPL_A_MSG，这是实际要传的数据
    memset(&wds_info,0,sizeof(wds_info));
    wds_info.role = send_param->role;
    wds_info.rssi = send_param->rssi;
    wds_info.wds_connect_status = send_param->wds_status;
    memcpy(wds_info.wds_ssid,send_param->ssid,sizeof(wds_info.wds_ssid));
    memcpy(wds_info.mac,send_param->mac,sizeof(wds_info.mac));
    strncpy(wds_info.sn, send_param->sn, strlen(send_param->sn));
	//The following are the new parameters
	wds_info.is_exist_expend = send_param->is_exist_expend;
	if(send_param->is_exist_expend){
		wds_info.expand_info.pw_stat = send_param->pw_stat;
		wds_info.expand_info.dev_nm_stat = send_param->dev_nm_stat;
		wds_info.expand_info.prj_nm_stat = send_param->prj_nm_stat;
		memcpy(wds_info.expand_info.dev_mac, send_param->dev_mac,sizeof(wds_info.expand_info.dev_mac));
		memcpy(wds_info.expand_info.ath_mac, send_param->ath_mac,sizeof(wds_info.expand_info.ath_mac));
		memcpy(wds_info.expand_info.dev_type, send_param->dev_type,sizeof(wds_info.expand_info.dev_type));
		memcpy(wds_info.expand_info.dev_name, send_param->dev_name,sizeof(wds_info.expand_info.dev_name));
		memcpy(wds_info.expand_info.prj_name, send_param->prj_name,sizeof(wds_info.expand_info.prj_name));
	}
    rc = nla_put(skb,DOC_EXMPL_A_MSG,sizeof(wds_info),&wds_info);
    if (rc != 0) {
        nlmsg_free(skb);
        return;
    }

    rc = genlmsg_end(skb,msg_hdr);//消息构建完成
    if (rc < 0) {
        nlmsg_free(skb);
        return;
    }

    rc = genlmsg_unicast(&init_net,skb,fd);
    if(rc != 0) {
        return;
    }
}
EXPORT_SYMBOL(send_date_to_app_beacon);

void send_date_to_app_keyerror(unsigned char keyerr_type, int connstate, unsigned char *ath_mac[MAC_ADDR_LEN], unsigned char *sn, unsigned char *dev_mac) {

    struct nlattr *na;
    struct sk_buff *skb;
    int rc;
    void *msg_hdr;
	int size;
    key_error_info_t key_error_info;

    if (fd <= 0) {
        return;
    }

    size = nla_total_size(sizeof(key_error_info_t));
    skb = genlmsg_new(size,GFP_ATOMIC);
    if(!skb) {
        return;
    }

    msg_hdr = genlmsg_put(skb,0,0,&doc_exmpl_genl_family,0,DOC_KEYERROR);
    if (msg_hdr == NULL) {
        nlmsg_free(skb);
        return;
    }

    //填充具体的netlink attribute:DOC_EXMPL_A_MSG，这是实际要传的数据
    memset(&key_error_info,0,sizeof(key_error_info_t));
	key_error_info.keyerr_type = keyerr_type;
    key_error_info.connstate = connstate;
	memcpy(key_error_info.ath_mac, ath_mac, sizeof(key_error_info.ath_mac));
	strncpy(key_error_info.sn, sn, strlen(sn));
	snprintf(key_error_info.dev_mac, sizeof(key_error_info.dev_mac), "%02x:%02x:%02x:%02x:%02x:%02x\n",
             (int)dev_mac[0], (int)dev_mac[1], (int)dev_mac[2], (int)dev_mac[3], (int)dev_mac[4], (int)dev_mac[5]);
    rc = nla_put(skb,DOC_EXMPL_A_KEYERROR,sizeof(key_error_info_t),&key_error_info);
    if (rc != 0) {
        nlmsg_free(skb);
        return;
    }

    rc = genlmsg_end(skb,msg_hdr);//消息构建完成
    if (rc < 0) {
        nlmsg_free(skb);
        return;
    }

    rc = genlmsg_unicast(&init_net,skb,fd);
    if(rc != 0) {
        return;
    }

}
EXPORT_SYMBOL(send_date_to_app_keyerror);

void send_data_to_app_fast_wds_info(fast_wds_info_t *fast_wds_info){
    struct nlattr *na;
    struct sk_buff *skb;
    int rc;
    void *msg_hdr;
	int size;
	fast_wds_info_t fast_wds_s;
    if (fd <= 0) {
        return;
    }
	size = nla_total_size(sizeof(fast_wds_info_t));
    skb = genlmsg_new(size,GFP_ATOMIC);
    if(!skb) {
        return;
    }
	msg_hdr = genlmsg_put(skb,0,0,&doc_exmpl_genl_family,0,DOC_FASR_WDS_INFO);
    if (msg_hdr == NULL) {
        nlmsg_free(skb);
        return;
    }
	/* 填充具体的netlink attribute:DOC_EXMPL_A_MSG，这是实际要传的数据 */
    memset(&fast_wds_s, 0, sizeof(fast_wds_info_t));
	memcpy(&fast_wds_s,fast_wds_info,sizeof(fast_wds_info_t));
	rc = nla_put(skb,DOC_EXMPL_A_KEYERROR,sizeof(fast_wds_info_t), &fast_wds_s);

    if (rc != 0) {
        nlmsg_free(skb);
        return;
    }

	rc = genlmsg_end(skb,msg_hdr);/* 消息构建完成 */
    if (rc < 0) {
        nlmsg_free(skb);
        return;
    }

	rc = genlmsg_unicast(&init_net,skb,fd);
    if(rc != 0) {
        return;
    }

}

void send_calibrate_rssi_to_app_ssid_and_key(rssi_calib_data_t *rssi_calib_data_s){
    struct nlattr *na;
    struct sk_buff *skb;
    int rc;
    void *msg_hdr;
	int size;
	rssi_calib_data_t rssi_calib_data;
    if (fd <= 0) {
        return;
    }
	size = nla_total_size(sizeof(rssi_calib_data_t));
    skb = genlmsg_new(size,GFP_ATOMIC);
    if(!skb) {
        return;
    }
	msg_hdr = genlmsg_put(skb,0,0,&doc_exmpl_genl_family,0,DOC_CALIBRATE_RSSI);
    if (msg_hdr == NULL) {
        nlmsg_free(skb);
        return;
    }
	/* 填充具体的netlink attribute:DOC_EXMPL_A_MSG，这是实际要传的数据 */
    memset(&rssi_calib_data, 0, sizeof(rssi_calib_data_t));
	memcpy(&rssi_calib_data,rssi_calib_data_s,sizeof(rssi_calib_data_t));
	rc = nla_put(skb,DOC_EXMPL_A_KEYERROR,sizeof(rssi_calib_data_t), &rssi_calib_data);

    if (rc != 0) {
        nlmsg_free(skb);
        return;
    }

	rc = genlmsg_end(skb,msg_hdr);/* 消息构建完成 */
    if (rc < 0) {
        nlmsg_free(skb);
        return;
    }

	rc = genlmsg_unicast(&init_net,skb,fd);
    if(rc != 0) {
        return;
    }

}

//echo command handler,接收一个msg并回复
int receve_date_from_app(struct sk_buff *skb2, struct genl_info *info) {
    struct nlattr *na;
    struct sk_buff *skb;
    int rc;
    void *msg_hdr;
    char *data;
    int i = 0;
    char buf[33];

    if(info == NULL) {
        goto error;
    }

    //对于每个属性，genl_info的域attrs可以索引到具体结构，里面有payload
    na = info->attrs[DOC_EXMPL_A_MSG];
    if (na) {
        data = (char *)nla_data(na);
        if(!data) {
            printk("Receive data error!\n");
        } else {
            strncpy(g_wdsbcn_ntvsn, (unsigned char *)data, sizeof(g_wdsbcn_ntvsn) - 1);
            printk("#WDS-BCN#%s\n", g_wdsbcn_ntvsn);
        }
    } else {
       printk("No info->attrs %d\n",DOC_EXMPL_A_MSG);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,14)
	fd = info->snd_portid;
#else
    fd = info->snd_pid;
#endif
    /*
    memset(buf,0,sizeof(buf));
    memcpy(buf,"cao",strlen("cao"));
    send_date_to_app_beacon(buf,1,2,3);
    */
    return 0;

    error:
    printk("Error occured in doc_echo!\n");
    return 0;
}

//将命令command echo和具体的handler对应起来
static struct genl_ops doc_exmpl_genl_ops_echo = {
    .cmd = DOC_EXMPL_C_ECHO,
    .flags = 0,
    .policy = doc_exmpl_genl_policy,
    .doit = receve_date_from_app,
    .dumpit = NULL,
};

//内核入口，注册generic netlink family/operations
static int __init genKernel_init(void) {
    int rc;
    printk("Generic Netlink Example Module inserted.\n");

    rc = genl_register_family(&doc_exmpl_genl_family);
    if (rc != 0) {
        goto failure;

    }
    rc = genl_register_ops(&doc_exmpl_genl_family,&doc_exmpl_genl_ops_echo);
    if (rc != 0) {
        printk("Register ops: %i\n",rc);
        genl_unregister_family(&doc_exmpl_genl_family);
        goto failure;
    }
#ifdef ESTBCN_REGISTER_MT7663_CB_SUPPORT
	mt7663_estwds_register_send_to_app_cb(send_date_to_app_beacon);
	mt7663_keyerror_register_send_to_app_cb(send_date_to_app_keyerror);
	mt7663_fast_wds_info_register_send_to_app_cb(send_data_to_app_fast_wds_info);
	mt7663_estrssi_register_send_to_app_cb(send_calibrate_rssi_to_app_ssid_and_key);
#endif
#ifdef ESTBCN_REGISTER_MT7628_CB_SUPPORT
	mt7628_estbcn_register_send_to_app_cb(send_date_to_app_beacon);
	printk("mt7628 estbcn register\n");
	mt7628_keyerror_register_send_to_app_cb(send_date_to_app_keyerror);
	mt7628_fast_wds_info_register_send_to_app_cb(send_data_to_app_fast_wds_info);
#endif
    return 0;

failure:
    printk("Error occured while inserting generic netlink example module\n");
    return -1;
}


static void __exit genKernel_exit(void) {
    int ret;
    printk("Generic Netlink Example Module unloaded.\n");

    ret = genl_unregister_ops(&doc_exmpl_genl_family,&doc_exmpl_genl_ops_echo);
    if(ret != 0) {
        printk("Unregister ops failed: %i\n",ret);
        return;
    }
    ret = genl_unregister_family(&doc_exmpl_genl_family);
    if(ret !=0) {
        printk("Unregister family failed:%i\n",ret);
    }
}

module_init(genKernel_init);
module_exit(genKernel_exit);
MODULE_LICENSE("GPL");
