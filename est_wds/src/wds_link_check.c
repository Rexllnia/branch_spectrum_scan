#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h> 
#include <sys/ioctl.h>    
#include <sys/socket.h>
#include <netinet/ether.h>   
#include <netpacket/packet.h>  
#include <netinet/in.h>
#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/ioctl.h>  
#include <errno.h>
#include <uci.h>

debug = 1;

#define DEBUG(fmt,args...)                                                           \
{                                                                                          \
    if (debug == 1) {                                                                        \
        printf("[%s]:[%d] "#fmt"\n",__func__,__LINE__,##args);           \
    }                                                                                      \
}


#define  ROLE_AP  1
#define  ROLE_CPE 0

#define FAIL    -1
#define SUCESS  0

#define WDS_CLIENT_SYNC 0
#define WDS_CLIENT_ACK  1

#define REBOOT_TIME 60*5
#define SEND_TIME 20


unsigned short checksum(unsigned short *buf, int nword);
int role;	 //0,表示cpe，1表示ap

struct wds_keep_live {
	int role;	 //0,表示cpe，1表示ap
	unsigned char name[20];
	unsigned char bssid[6];
};

struct cpe_list {
	unsigned char receve_status;
	unsigned long receve_timeout;
	unsigned char cpe_mac[6];
	struct cpe_list *next;
};


struct wds_keep_live wds_packet_t;
struct cpe_list *cpe_dev_p = NULL;

unsigned char receve_status;
unsigned char src_mac[6];
unsigned char *ifname = "eth0";
unsigned char broadcast_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char dst_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};


char wds_status = WDS_CLIENT_SYNC;


void dump_date(unsigned char *buf,int len){
	int i;
	if (debug) {
		for(i=0; len; ++i)  
		{  
		  DEBUG(" %02x", buf[i]);  
		  if((i + 1) % 16 == 0)  
		  {  
			DEBUG("\n");  
		  }  
		}  
	}
}


int load_uci_config(char *type,char *name,char *option_name,char *buf)
{
    struct uci_package * pkg = NULL;
    struct uci_element *e,*e_list;
	struct uci_option * o;
	struct led_event *p_event;
	struct uci_context * ctx = NULL;
    char *tmp;
    const char *value;
    char ret = FAIL;

    ctx = uci_alloc_context();
    if (UCI_OK != uci_load(ctx, UCI_CONFIG_FILE, &pkg))
        goto cleanup;

    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
		if (s->anonymous == 1) {
			continue;
		}
        if(!strcmp(name,s->e.name)  && !strcmp(type,s->type))
        {
            if (NULL != (value = uci_lookup_option_string(ctx, s,option_name))){
                strcpy(buf,value);
				DEBUG("buf %s",buf);
				ret = SUCESS;
            }
		}
	}
    uci_unload(ctx, pkg);
cleanup:
    uci_free_context(ctx);
    ctx = NULL;
	return ret;
}


//获取当前锁定状态
int get_lock_status() {
	char buf[100];
}


//获取当前设备角色
int get_role() {
	
	role = 0;
}

//获取对端的BSSID
int get_bssid() {
	wds_packet_t.bssid[1] = 0x01;
	wds_packet_t.bssid[5] = 0x05;
}

//重启设备，并标记曾经重启过
int reboot_cpe()
{
	DEBUG("");
}

//重启设备，并标记曾经重启过
int int_cpe()
{
	DEBUG("");
}

//重启设备，并标记曾经重启过
int reboot_ap()
{
	DEBUG("");
}

//重启设备，并标记曾经重启过
int int_ap()
{
	DEBUG("");
}


//写入消息，消息包含 bssid
int int_packet()
{
	memset(&wds_packet_t,0,sizeof(struct wds_keep_live));
	//wds_packet_t.role = role;
	wds_packet_t.role = 1;
	memcpy(wds_packet_t.name,"ruijie",strlen("ruijie"));
	get_bssid();
}

//获取当前br-wan mac地址
int get_mac(char *ifname,unsigned char *mac)
{  
    int  sockfd;  
    struct sockaddr_in  sin;  
    struct ifreq ifr;  
      
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    if (sockfd == -1) {
        perror("socket error");  
        return FAIL;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);      //Interface name
            
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {  //SIOCGIFHWADDR 获取hardware address  
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);  
        DEBUG("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); 
		return SUCESS;
    }
      
    return FAIL;  
}  

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  
    int * id = (int *)arg;  
    struct wds_keep_live *wds_receve;
	struct cpe_list *cpe_list_p;
    struct sysinfo info; 
	
    DEBUG("id: %d\n", ++(*id));  
    DEBUG("Packet length: %d\n", pkthdr->len);  
    DEBUG("Number of bytes: %d\n", pkthdr->caplen);  
    DEBUG("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
      
    int i;  
	
    wds_receve = (struct wds_keep_live *)((u_char*)packet + 42);
	DEBUG("name %s", wds_receve->name); 
	
	//cpe 模式
	if (role == 0) {
		//丢弃 广播报文，比对接收到的报文的前面6个字节
		if (strncmp(packet,broadcast_mac,sizeof(broadcast_mac)) == 0) {
			return SUCESS;
		} else if (strncmp(wds_receve->bssid,wds_packet_t.bssid,sizeof(broadcast_mac)) == 0) {
			receve_status = 1;
			strncpy(dst_mac, packet + 6, sizeof(broadcast_mac));
		} 
	} else if (role == 1) {  //ap模式下
		// AP模式下当接收到报文之后，判断是否和本地的SSID一样，如果一样则说明是对端发送的报文
		if (strncmp(wds_receve->bssid,wds_packet_t.bssid,sizeof(broadcast_mac)) == 0) {
			cpe_list_p = cpe_dev_p;
			if (cpe_list_p == NULL) {
				cpe_dev_p = (struct cpe_list *)malloc (sizeof (struct cpe_list)); 
				memset(cpe_dev_p,0,sizeof(struct cpe_list));
				cpe_list_p = cpe_dev_p;
				strncpy(cpe_list_p->cpe_mac, packet + 6, sizeof(broadcast_mac));
			} else {
				while (cpe_list_p->next != NULL) {
					//表示一样
					if (strncmp(cpe_list_p->cpe_mac,packet + 6,sizeof(broadcast_mac)) == 0) {
						break;
					}
				}
				if (cpe_list_p->next == NULL) {
					cpe_list_p->next = (struct cpe_list *)malloc (sizeof (struct cpe_list)); 
					memset(cpe_list_p->next,0,sizeof(struct cpe_list));
					cpe_list_p = cpe_list_p->next;
					strncpy(cpe_list_p->cpe_mac, packet + 6, sizeof(broadcast_mac));
				}
			}
			cpe_list_p->receve_status = 1;
			if (sysinfo(&info) == 0) {
				cpe_list_p->receve_timeout = info.uptime + 5*60;
				DEBUG("receve_timeout %ld ",cpe_list_p->receve_timeout);
			}
		}
	}

    DEBUG("\n\n");  

}

int revece_pactek()
{
	DEBUG("");
	char errBuf[PCAP_ERRBUF_SIZE], *devStr;  
	
	/* open a device, wait until a packet arrives */ 
	//pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
	//snaplen是整形的，它定义了将被pcap捕捉的最大字节数
	//当promisc设为true时将置指定接口为混杂模式
	//to_ms是读取时的超时值，单位是毫秒(假如为0则一直嗅探直到错误发生，为-1则不确定)
	pcap_t * device = pcap_open_live(ifname, 2000, 0, 0, errBuf);
	
	if(!device)  
	{  
		printf("error: pcap_open_live(): %s\n", errBuf);  
		return FAIL;  
	}  
	  
	/* construct a filter */  
	struct bpf_program filter;	
	pcap_compile(device, &filter, "dst port 50001", 1, 0);	
	pcap_setfilter(device, &filter);  
	
	/* wait loop forever */  
	int id = 0;  
	pcap_loop(device, -1, getPacket, (u_char*)&id);  
	  
	pcap_close(device);  
	DEBUG("");

	return FAIL;
}

int process()
{
	unsigned char *tmp;
	int len;
	char wds_sync_fail_count = 0;
	pthread_t thread_revice;
	struct cpe_list *p;
	struct sysinfo info;
	int ap_flag;
	
	memset(src_mac,0,sizeof(src_mac));
	if (FAIL == get_mac(ifname,src_mac)) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}

    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw_fd < 0) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}

    unsigned char send_msg[1024] = {
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //dst_mac: 74-27-EA-B5-FF-D8
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //src_mac: c8:9c:dc:b7:0f:19
     0x08, 0x00,                        //以太网包类型

     0x45, 0x00, 0x00, 0x00,     //
     0x00, 0x00, 0x00, 0x00,    //
     0x80, 17,  0x00, 0x00,    //
     255,  255,  255,  255,    //src_ip: 255.255.255.255
     255,  255,  255,  255,    //dst_ip: 255.255.255.255

     0xc3, 0x51, 0xc3, 0x51,            //port 50001
     0x00, 0x00, 0x00, 0x00,            //
    };
   	tmp = send_msg + 6;
	memcpy(tmp,src_mac,sizeof(src_mac));

	int_packet();
	
    //len = sprintf(send_msg+42, "%s", wds_packet_t.name);
    memcpy(send_msg + 42,&wds_packet_t,sizeof(struct wds_keep_live));
    if((len = sizeof(struct wds_keep_live)) % 2 == 1)
    {
        len++;
    }
   
    *((unsigned short *)&send_msg[16]) = htons(20+8+len);
    *((unsigned short *)&send_msg[14+20+4]) = htons(8+len);

    unsigned char pseudo_head[1024] = {
		255,  255,	255,  255,	  //src_ip: 10.221.20.11
		255,  255,	255,  255,	  //dst_ip: 10.221.20.10
        0x00, 17,  0x00, 0x00,    // 
    };
   
    *((unsigned short *)&pseudo_head[10]) = htons(8 + len); 
    memcpy(pseudo_head+12, send_msg+34, 8+len); 
    *((unsigned short *)&send_msg[24]) = htons(checksum((unsigned short *)(send_msg+14),20/2));
    *((unsigned short *)&send_msg[40]) = htons(checksum((unsigned short *)pseudo_head,(12+8+len)/2));

    struct sockaddr_ll sll;
    struct ifreq ethreq;
   
    strncpy(ethreq.ifr_name, ifname, IFNAMSIZ);
    if(-1 == ioctl(sock_raw_fd, SIOCGIFINDEX, &ethreq))
    {
        perror("ioctl");
        close(sock_raw_fd);
        return FAIL;
    }
   
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex;

	//开启接收线程
	if (0 != pthread_create(&thread_revice,NULL,revece_pactek,NULL)) {
		printf("%s %d error \n",__func__,__LINE__);
	}
	
	pthread_join(thread_revice, NULL);
	DEBUG("");
	while (1) {
		if (role == 0) {
			switch (wds_status) {
				//cpe 模式下的 同步建立状态，这种状态下只管发送报文
				case WDS_CLIENT_SYNC:
					len = sendto(sock_raw_fd, send_msg, 14+20+8+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
					dump_date(send_msg,sizeof(send_msg));
					if(len == -1) {
						continue;
					}
					//等待数据到达
					sleep(SEND_TIME/2);
					if (receve_status == 1) {
						wds_sync_fail_count = 0;
						receve_status = 0;
						wds_status = WDS_CLIENT_ACK;
						strncpy(send_msg, dst_mac, sizeof(broadcast_mac));
					} else {
						//如果cpe 曾经连接成功，但是现在却无法通信，则说明环境发送改变或者是设备故障，直接重启设备
						//一直处于未连接状态则不做处理，有可能CPE有上电，但是AP没上电，这种情况很正常
					    wds_sync_fail_count++;
						if (wds_sync_fail_count >= REBOOT_TIME/SEND_TIME) {
							wds_sync_fail_count = 0;
							reboot_cpe();
						}
					}
				case WDS_CLIENT_ACK:
					//单播
					len = sendto(sock_raw_fd, send_msg, 14+20+8+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
					if(len == -1) {
						continue;
					}						
					//等待数据到达
					sleep(SEND_TIME/2);
					if (receve_status == 1) {
						wds_sync_fail_count = 0;
						receve_status = 0;
					} else {
						//回到初始状态
						wds_status = WDS_CLIENT_SYNC;
						wds_sync_fail_count++;
						if (wds_sync_fail_count >= REBOOT_TIME/SEND_TIME) {
							wds_sync_fail_count = 0;
							reboot_cpe();
						}				
					}
					
			}
		} else if (role == 1) {
			p = cpe_dev_p;
			ap_flag = 0;
			while (p != NULL) {
				if (p->receve_status == 1) {
					//收到报文，回应
					ap_flag = 1;
					strncpy(send_msg, p->cpe_mac, sizeof(broadcast_mac));
					len = sendto(sock_raw_fd, send_msg, 14+20+8+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
					if(len == -1) {
						continue;
					}
					p->receve_status = 0;
				} else {
				    if (sysinfo(&info) == 0) {
				        if (p->receve_timeout != 0 && info.uptime > p->receve_timeout && ap_flag != 0) {
							ap_flag = 0;
						}
				    }					
				}
				p = p->next;
			}
			if (ap_flag == 0) {
				reboot_ap();				
			}
		}
		if (role == 0) {
			sleep(SEND_TIME/2);
		} else {
			sleep(1);
		}
	}
}
int main(int argc, char *argv[])
{
	process();
}

unsigned short checksum(unsigned short *buf, int nword)
{
    unsigned long sum;
    for(sum = 0; nword > 0; nword--)
    {
        sum += htons(*buf);
        buf++;
    }
    sum = (sum>>16) + (sum&0xffff);
    sum += (sum>>16);
    return ~sum;
}

