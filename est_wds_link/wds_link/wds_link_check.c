/*
 * Copyright(C) 2015 Ruijie Network. All rights reserved.
 */
/*
 * 
 * est 301 302 wds 链路检测   zhengjunqiang@ruijie.com.cn
 *
 * History 
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/kthread.h>
#include <linux/err.h>

extern struct sk_buff *arp_create(int type, int ptype, __be32 dest_ip,
			   struct net_device *dev, __be32 src_ip,
			   const unsigned char *dest_hw,
			   const unsigned char *src_hw,
			   const unsigned char *target_hw);

static int wds_link_rcv(struct sk_buff *skb, struct net_device *dev,		   
              struct packet_type *pt, struct net_device *orig_dev);


#define INFO  1
#define ERROR 0

#define LINK_STATUS       1
#define UNLINK_STATUS     0

int debug = 1;

#define LOG_DEBUG(level,fmt,args...)                                                           \
{                                                                                          \
    if (level <= debug) {                                                                        \
        printk("[%s]:[%d] "#fmt"\n",__func__,__LINE__,##args);           \
    }                                                                                      \
}

typedef struct wds_link_status {
	char status;
	char interface_name[50];
	struct net_device *dev;
	unsigned char da[ETH_ALEN];
} wds_link_status_t;

wds_link_status_t wds_link_t;

static struct packet_type wds_link_packet_type __read_mostly = 
{	
    .type		= cpu_to_be16(ETH_P_DEC),	
	.func		= wds_link_rcv,
};

void skb_dump(struct sk_buff* skb) 
{
	unsigned int i;	
    LOG_DEBUG(INFO,"skb_dump: from %s with len %d (%d) headroom=%d tailroom=%d\n",
			skb->dev?skb->dev->name:"ip stack",skb->len,skb->truesize,
			skb_headroom(skb),skb_tailroom(skb));
    
    for (i = 0; i < skb->len; i++) {
        if (i % 16 == 0) LOG_DEBUG(INFO,"%#4.4x", i);
        if (i % 2 == 0) LOG_DEBUG(INFO," ");
        LOG_DEBUG(INFO,"%2.2x", ((unsigned char *)skb)[i]);
        if (i % 16 == 15) LOG_DEBUG(INFO,"\n");
    }
	LOG_DEBUG(INFO,"\n");
}

//获取brname 并转化为net device
void wds_get_brname(void)
{
	char *if_name = "br-lan";
	struct net_device *dev;
		
	while(1) {
		dev = dev_get_by_name(&init_net, if_name);
		if (dev == NULL) {
			LOG_DEBUG(ERROR,"dev is null ,try agina!");
			msleep(1000);
		} else {
			wds_link_t.dev = dev;
			LOG_DEBUG(INFO,"name %s",dev->name);
			break;
		}
	}
}

void wds_create_frame(void)
{
	struct sk_buff *skb;
	unsigned char da_all[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	
	LOG_DEBUG(INFO,"mac %s",wds_link_t.dev->dev_addr);
	skb = arp_create(1,ETH_P_DEC,0,wds_link_t.dev,0,da_all,wds_link_t.dev->dev_addr,NULL);
    if (skb != NULL) {
        dev_queue_xmit(skb);
    } else {
       LOG_DEBUG(ERROR, "%s: Transmit Packet fail...\n", wds_link_t.dev->name);
    }	
}

static int wds_link_rcv(struct sk_buff *skb, struct net_device *dev,		   
              struct packet_type *pt, struct net_device *orig_dev)
{	    
	skb_dump(skb);
    kfree_skb(skb);	
  	//链路检测一定是ath之间进行转发的，所以当收到这个报文的时候，处理结束之后就开始单播，不进行转发
    return NET_RX_DROP;
}

int threadfunc(void *data)
{
    while(1) {
		LOG_DEBUG(INFO,"threadfunc");
		if (wds_link_t.dev == NULL) {
			wds_get_brname();
		}
		
		wds_create_frame();
		msleep(1000);
		if (kthread_should_stop()) {
			break;
		}
    }
    return 0;
}


static struct task_struct *wds_task;
int __init wds_link_device_init(void)
{
	int err;
    dev_add_pack(&wds_link_packet_type);
	LOG_DEBUG(INFO,"INIT");

    wds_task = kthread_create(threadfunc, NULL, "wds_task");

    if (IS_ERR(wds_task)) {
        err = PTR_ERR(wds_task);
        wds_task = NULL;
        return err;
    }
	wake_up_process(wds_task);
	return 0;
}

void __exit wds_link_device_exit(void)
{
    dev_remove_pack(&wds_link_packet_type);
	if (wds_task != NULL) {
		kthread_stop(wds_task);
	}
	LOG_DEBUG(INFO,"EXIT");
}

module_init(wds_link_device_init);
module_exit(wds_link_device_exit);
MODULE_LICENSE("Dual BSD/GPL");

