#include "rg_wds.h"

/*
type:set/get/info  0/1/2/
    set:设置即可
    get:获取信息，通过shell执行
    info:发送一般信息
dest:sn
    目标设备
dest:sn#type:set#cmd:具体指令
dest:sn#type:info#role:cpe/ap#lock::on/off#
*/

#define LIST_ALL_PAGE_SIZE  4
#define DEV_MULTI_MAXCNT    200

int g_dev_multi_info_cnt = 0;
struct dev_multi_info *rg_wds_all_info = NULL;
pthread_mutex_t mtx_rg_wds_all_info;


char *rg_wds_to_set_middle(char *buf) {
    memcpy(buf,":",1);
    return buf + 1;
}

char *rg_wds_to_set_end(char *buf) {
    memcpy(buf,"#",1);
    return buf + 1;
}

char *rg_wds_to_set_begin(char *buf) {
    memcpy(buf,"#",1);
    return buf + 1;
}

char * rg_wds_to_dev_head(char mem_type,char *sn,char *buf) {
    char *p = buf;

    memcpy(p,"dest",strlen("dest"));
    p += strlen("dest");
    p = rg_wds_to_set_middle(p);

    memcpy(p,sn,strlen(sn));
    p += strlen(sn);
    p = rg_wds_to_set_end(p);

    memcpy(p,"type",strlen("type"));
    p += strlen("type");
    p = rg_wds_to_set_middle(p);

    switch (mem_type) {
        case TYPE_SET:
            memcpy(p,"set",strlen("set"));
            p += strlen("set");
            break;
        case TYPE_GET:
            memcpy(p,"get",strlen("get"));
            p += strlen("get");
            break;
        case TYPE_INFO:
        default:
            memcpy(p,"info",strlen("info"));
            p += strlen("info");
    }
    p = rg_wds_to_set_end(p);
    return p;
}

char * rg_wds_to_dev_body(char *buf,char *str) {
    char *p = buf;

    memcpy(p,str,strlen(str));
    p += strlen(str);
}

void rg_wds_to_dev_message(char type,char *sn,char *buf,char *str) {
    char *p = buf;

    p = rg_wds_to_set_begin(p);
    p = rg_wds_to_dev_head(type,sn,p);
    p = rg_wds_to_dev_body(p,str);
    p = rg_wds_to_set_end(p);
}

//根据SN判断是否是发送给自己的
char rg_wds_check_1(char *str) {
    int i = 0;
    char *p;

    while(str[i] != ':' && str[i] != 0) {
        i++;
    }

    if (str[i] == ':') {
        p = str + i + 1;
        if (memcmp(p,rg_dev_info_t.sn,strlen(rg_dev_info_t.sn)) == 0 || memcmp(p,"all",strlen("all")) == 0) {
            return 1;
        }
    }
    return 0;
}

//消息类型
char rg_wds_type_process(char *str) {
    int i = 0;
    char *p;

    while(str[i] != ':' && str[i] != 0) {
        i++;
    }

    if (str[i] == ':') {
        p = str + i + 1;
        if (memcmp(p,"set",strlen("set")) == 0) {
            return TYPE_SET;
        } else if (memcmp(p,"get",strlen("get")) == 0) {
            return TYPE_GET;
        } else if (memcmp(p,"info",strlen("info")) == 0) {
            return TYPE_INFO;
        }
    }
    return 0;
}

//命令执行
//#ls &#
void rg_wds_set_process(char *str) {
    char i = 1;
    char *p = str;

    if (strlen(str) < 2) {
        return;
    }

    str[strlen(str) - 1] = 0;
    DEBUG("str %s",str + 1);

    rg_wds_get_cmd(str + 1);
}

char *rg_wds_info_item_filter(char *buf) {
    if ((buf - 1) != NULL && *(buf - 1) == ';') {
        return buf;
    }
    memcpy(buf,";",1);
    return buf + 1;
}

char *rg_wds_info_item_str(char *option,char *value,char *buf) {
    char *p = buf;
    if (strlen(value) == 0) {
        return p;
    }
    memcpy(p,option,strlen(option));
    p = p + strlen(option);
    memcpy(p,":",strlen(":"));
    p = p + strlen(":");
    memcpy(p,value,strlen(value));
    p = p + strlen(value);
    return p;
}

char *rg_wds_info_item_str_len(char *option,char *value,int len,char buf) {
    char *p = buf;

    memcpy(p,option,strlen(option));
    p = p + strlen(option);
    memcpy(p,":",strlen(":"));
    p = p + strlen(":");
    memcpy(p,value,len);
    p = p + len;
}

/*
char *rg_wds_info_item_num(char *option,unsigned int value,char buf) {
    char *p = buf;

    memcpy(p,option,strlen(option));
    p = p + strlen(option);
    memcpy(p,":",strlen(":"));
    p = p + strlen(":");

    (unsigned int) (char *) p = (unsigned int)value;
    p = p + sizeof(value);
}
*/

void rg_wds_set_array_value(int value,int array[],int len) {
    array[array[len - 1]] = value;
    array[len - 1] = array[len - 1] + 1;
    if (array[len - 1] == len - 1 - 1) {
        array[len - 1] = 0;
    }
    //DEBUG("value %d array[len - 1] %d len %d",value,array[len - 1],len);
}

unsigned int rg_wds_get_array_average(int array[],int len) {
    int i = 0;
    int count = 0;
    long sum = 0;
    //DEBUG("");
    for (i = 0;i < (len - 1);i++) {
        if (array[i] != 0) {
            //DEBUG("array[%d] = %d,count %d",i,array[i],count + 1);
            sum += array[i];
            count++;
        }
    }
    if (count == 0) {
        return 0;
    }
    //DEBUG("average %d",sum/count);
    return sum/count;
}

static int tx_speed_a[100];
static int rx_speed_a[100];
static int rssi_a[100];
static int chutil_a[100];

char *rg_wds_info_body(char *buf) {
    char *p = buf;
    char str[100];
    char str_2[100];
    static unsigned char flag = 0;
    static unsigned long time_now;
    struct sysinfo info;

	//获取当前时间
	sysinfo(&info);

    p = rg_wds_info_item_str("sn",rg_dev_info_t.sn,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("hostname",rg_dev_info_t.host_name,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("ssid",rg_ath_info_t.ssid,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
    sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",
                                            rg_dev_info_t.sys_mac[0],
                                            rg_dev_info_t.sys_mac[1],
                                            rg_dev_info_t.sys_mac[2],
                                            rg_dev_info_t.sys_mac[3],
                                            rg_dev_info_t.sys_mac[4],
                                            rg_dev_info_t.sys_mac[5]);
    p = rg_wds_info_item_str("sysmac",str,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("model",rg_dev_info_t.dev_type,p);
    p = rg_wds_info_item_filter(p);

    if (rg_ath_info_t.role == MODE_AP) {
        p = rg_wds_info_item_str("role","ap",p);
        p = rg_wds_info_item_filter(p);
    } else {
        p = rg_wds_info_item_str("role","cpe",p);
        p = rg_wds_info_item_filter(p);
    }

    if (rg_gpio_info_t.gpio_lock_value == LOCK) {
        p = rg_wds_info_item_str("lock","true",p);
        p = rg_wds_info_item_filter(p);
    } else {
        p = rg_wds_info_item_str("lock","false",p);
        p = rg_wds_info_item_filter(p);
    }

    memset(str,0,sizeof(str));
    sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",
                                            rg_ath_info_t.root_mac_hex[0],
                                            rg_ath_info_t.root_mac_hex[1],
                                            rg_ath_info_t.root_mac_hex[2],
                                            rg_ath_info_t.root_mac_hex[3],
                                            rg_ath_info_t.root_mac_hex[4],
                                            rg_ath_info_t.root_mac_hex[5]);
    p = rg_wds_info_item_str("athmac",str,p);
    p = rg_wds_info_item_filter(p);

    if (rg_ath_info_t.role == MODE_CPE && rg_pair_info_heap_t != NULL) {
        p = rg_wds_info_item_str("peersn",rg_pair_info_heap_t->pair_dev_info_t.sn,p);
        p = rg_wds_info_item_filter(p);
    }

    if (rg_ath_info_t.role == MODE_CPE && rg_pair_info_heap_t != NULL) {
        memset(str,0,sizeof(str));
        sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",
                                                rg_pair_info_heap_t->mac[0],
                                                rg_pair_info_heap_t->mac[1],
                                                rg_pair_info_heap_t->mac[2],
                                                rg_pair_info_heap_t->mac[3],
                                                rg_pair_info_heap_t->mac[4],
                                                rg_pair_info_heap_t->mac[5]);
        p = rg_wds_info_item_str("peermac",str,p);
        p = rg_wds_info_item_filter(p);
    }

    p = rg_wds_info_item_str("softversion",rg_dev_info_t.software_version,p);
    p = rg_wds_info_item_filter(p);

    struct in_addr in;
    in.s_addr = rg_dev_info_t.ip;

    p = rg_wds_info_item_str("userIp",inet_ntoa(in),p);
    p = rg_wds_info_item_filter(p);

    if (rg_wds_est_radio_type(rg_dev_info_t.dev_type) == EST_2G) {
        p = rg_wds_info_item_str("band","2.4G",p);
        p = rg_wds_info_item_filter(p);
    } else if (rg_wds_est_radio_type(rg_dev_info_t.dev_type) == EST_5G) {
        p = rg_wds_info_item_str("band","5.8G",p);
        p = rg_wds_info_item_filter(p);
    }

    memset(str,0,sizeof(str));
    sprintf(str,"%d",info.uptime);
    p = rg_wds_info_item_str("onlineTime",str,p);
    p = rg_wds_info_item_filter(p);

    if (rg_ath_info_t.role == MODE_CPE && rg_pair_info_heap_t != NULL) {
        int rssi;
        rssi = rg_pair_info_heap_t->pair_assioc_info_t.rssi - 95;
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rssi);
        p = rg_wds_info_item_str("rssi",str,p);
        p = rg_wds_info_item_filter(p);

        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.rxrate);
        p = rg_wds_info_item_str("rate",str,p);
        p = rg_wds_info_item_filter(p);

        p = rg_wds_info_item_str("phymode",rg_pair_info_heap_t->pair_assioc_info_t.phymode,p);
        p = rg_wds_info_item_filter(p);

        rg_wds_set_array_value(rssi,rssi_a,sizeof(rssi_a)/sizeof(int));
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_wds_get_array_average(rssi_a,sizeof(rssi_a)/sizeof(int)));
        p = rg_wds_info_item_str("rssi_a",str,p);
        p = rg_wds_info_item_filter(p);
    }

    if (rg_pair_info_heap_t != NULL) {
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.channel);
        p = rg_wds_info_item_str("channel",str,p);
        p = rg_wds_info_item_filter(p);
    } else {
        memset(str,0,sizeof(str));
        memset(str_2,0,sizeof(str_2));
        if (rg_wds_est_radio_type(rg_dev_info_t.dev_type) == EST_2G) {
            sprintf(str,"uci get wireless.wifi%d.channel",0);
        } else if (rg_wds_est_radio_type(rg_dev_info_t.dev_type) == EST_5G) {
            sprintf(str,"uci get wireless.wifi%d.channel",1);
        }

        rg_wds_misc_cmd(str,str_2,sizeof(str_2));
        p = rg_wds_info_item_str("channel",str_2,p);
        p = rg_wds_info_item_filter(p);
    }

    memset(str,0,sizeof(str));
    rg_wds_misc_read_file("/etc/rg_config/admin",str,sizeof(str));
    if (strlen(str) == 0) {
        memcpy(str,"U2FsdGVkX1/tV9LOvYktw6g4bq+wzr5TEtX9/cAMwXc=",strlen("U2FsdGVkX1/tV9LOvYktw6g4bq+wzr5TEtX9/cAMwXc="));
    }
    p = rg_wds_info_item_str("passwd",str,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
    memset(str_2,0,sizeof(str_2));
    sprintf(str_2,"iwpriv %s get_channf | awk -F \":\" '{print $2}'",rg_ath_info_t.ath_wsd_name);
    rg_wds_misc_cmd(str_2,str,sizeof(str));
    p = rg_wds_info_item_str("channf",str,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
    memset(str_2,0,sizeof(str_2));
    sprintf(str_2,"iwpriv %s get_chutil | awk -F \":\" '{print $2}'",rg_ath_info_t.ath_wsd_name);
    rg_wds_misc_cmd(str_2,str,sizeof(str));
    p = rg_wds_info_item_str("chutil",str,p);
    p = rg_wds_info_item_filter(p);
    //平均空口利用率
    rg_wds_set_array_value(atoi(str),chutil_a,sizeof(chutil_a)/sizeof(int));
    memset(str,0,sizeof(str));
    sprintf(str,"%d",rg_wds_get_array_average(chutil_a,sizeof(chutil_a)/sizeof(int)));
    p = rg_wds_info_item_str("chutil_a",str,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("distance",rg_ath_info_t.wds_distance,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("txpower",rg_ath_info_t.wds_txpower,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
    rg_wds_misc_get_iface_netmask("br-wan",str);
    p = rg_wds_info_item_str("netmask",str,p);
    p = rg_wds_info_item_filter(p);

    if (rg_pair_info_heap_t != NULL) {
        p = rg_wds_info_item_str("onlinestatus","online",p);
        p = rg_wds_info_item_filter(p);
    } else {
        p = rg_wds_info_item_str("onlinestatus","offline",p);
        p = rg_wds_info_item_filter(p);
    }

    memset(str,0,sizeof(str));
    rg_wds_misc_cmd("uci get cwmp.status.SessionRetryTimes",str,sizeof(str));
    if (strcmp(str,"0") == 0) {
        p = rg_wds_info_item_str("cwmp","on",p);
        p = rg_wds_info_item_filter(p);
    } else {
        p = rg_wds_info_item_str("cwmp","off",p);
        p = rg_wds_info_item_filter(p);
    }

    //一分钟发送一次
    if (time_now == 0 || (info.uptime - time_now) > 5) {
        time_now = info.uptime;
        if (rg_wds_est_is_phy_key(rg_dev_info_t.dev_type) == false) {
            char speed[10];
            char link[10];
            char duplex[10];
            memset(speed,0,sizeof(speed));
            memset(link,0,sizeof(link));
            memset(duplex,0,sizeof(duplex));
            rg_wds_sw_status_status("eth1",1,link,speed,duplex);

            p = rg_wds_info_item_str("lan1speed",speed,p);
            p = rg_wds_info_item_filter(p);

            p = rg_wds_info_item_str("lan1link",link,p);
            p = rg_wds_info_item_filter(p);

            p = rg_wds_info_item_str("lan1duplex",duplex,p);
            p = rg_wds_info_item_filter(p);
         } else {
            int i = 1;
            char speed[10];
            char link[10];
            char duplex[10];
            for (i = 1;i <= 2;i++) {
                memset(speed,0,sizeof(speed));
                memset(link,0,sizeof(link));
                memset(duplex,0,sizeof(duplex));
                rg_wds_sw_status_status("eth1",i,link,speed,duplex);

                memset(str,0,sizeof(str));
                sprintf(str,"lan%dspeed",i);
                p = rg_wds_info_item_str(str,speed,p);
                p = rg_wds_info_item_filter(p);

                memset(str,0,sizeof(str));
                sprintf(str,"lan%dlink",i);
                p = rg_wds_info_item_str(str,link,p);
                p = rg_wds_info_item_filter(p);

                memset(str,0,sizeof(str));
                sprintf(str,"lan%dduplex",i);
                p = rg_wds_info_item_str(str,duplex,p);
                p = rg_wds_info_item_filter(p);
            }
        }
    }
    unsigned long rx_rate = 0;
    unsigned long tx_rate = 0;
    rg_wds_get_dev_flow(&rx_rate,&tx_rate);
    //DEBUG("rx_rate %d tx_rate %d",rx_rate,tx_rate);
    memset(str,0,sizeof(str));
    sprintf(str,"%d",rx_rate);
    p = rg_wds_info_item_str("rx_rate",str,p);
    p = rg_wds_info_item_filter(p);

    memset(str,0,sizeof(str));
    sprintf(str,"%d",tx_rate);
    p = rg_wds_info_item_str("tx_rate",str,p);
    p = rg_wds_info_item_filter(p);

    p = rg_wds_info_item_str("hardversion",rg_dev_info_t.hardware_version,p);
    p = rg_wds_info_item_filter(p);

    if (rg_ath_info_t.role == MODE_CPE && rg_pair_info_heap_t != NULL) {
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.rxrate);
        p = rg_wds_info_item_str("rx_speed",str,p);
        p = rg_wds_info_item_filter(p);

        rg_wds_set_array_value(rg_pair_info_heap_t->pair_assioc_info_t.rxrate,rx_speed_a,sizeof(rx_speed_a)/sizeof(int));
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_wds_get_array_average(rx_speed_a,sizeof(rx_speed_a)/sizeof(int)));
        p = rg_wds_info_item_str("rx_speed_a",str,p);
        p = rg_wds_info_item_filter(p);

        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.txrate);
        p = rg_wds_info_item_str("tx_speed",str,p);
        p = rg_wds_info_item_filter(p);

        rg_wds_set_array_value(rg_pair_info_heap_t->pair_assioc_info_t.txrate,tx_speed_a,sizeof(tx_speed_a)/sizeof(int));
        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_wds_get_array_average(tx_speed_a,sizeof(tx_speed_a)/sizeof(int)));
        p = rg_wds_info_item_str("tx_speed_a",str,p);
        p = rg_wds_info_item_filter(p);

        memset(str,0,sizeof(str));
        rg_wds_misc_read_file("/tmp/.tipc_ping_time",str,sizeof(str));
        p = rg_wds_info_item_str("pingTime",str,p);
        p = rg_wds_info_item_filter(p);

        memset(str,0,sizeof(str));
        sprintf(str,"%d",rg_pair_info_heap_t->pair_assioc_info_t.assioc_time);
        p = rg_wds_info_item_str("connectTime",str,p);
        p = rg_wds_info_item_filter(p);
    }

	memset(str,0,sizeof(str));
	rg_wds_json_first("/etc/rg_config/networkid.json","networkId",str,sizeof(str));
	if (strlen(str) == 0) {
		strcpy(str,"0");
	}
	p = rg_wds_info_item_str("networkId",str,p);
	p = rg_wds_info_item_filter(p);


	memset(str,0,sizeof(str));
	rg_wds_json_first("/etc/rg_config/networkid.json","networkName",str,sizeof(str));
	if (strlen(str) == 0) {
		strcpy(str,"default");
	}
	p = rg_wds_info_item_str("networkName",str,p);
	p = rg_wds_info_item_filter(p);

    return p;
}

void rg_wds_send_info(char *buf) {
    char *p = buf;

    p = rg_wds_to_set_begin(p);
    p = rg_wds_to_dev_head(TYPE_INFO,"all",p);
    p = rg_wds_info_body(p);
    p = rg_wds_to_set_end(p);
    //DEBUG("buf %s len %d",buf,strlen(buf));
}

void rg_wds_send_all() {
    struct mac_ip_udp_wds_packet eth_heap_p;
    char buf[2000];
    int len = 0;

    memset(buf,0,sizeof(buf));
    memset(&eth_heap_p,0,sizeof(struct mac_ip_udp_wds_packet));
    rg_wds_send_date_head_init(&eth_heap_p);

	memcpy(buf,&eth_heap_p,sizeof(struct mac_ip_udp_wds_packet));
    len += sizeof(struct mac_ip_udp_wds_packet);

    rg_wds_send_info(buf + len);
    len = len + strlen(len + buf);

	rg_send_raw_date_2("br-wan",len,buf,NULL);
    rg_wds_message_dev_process(buf + sizeof(struct mac_ip_udp_wds_packet));
}

void rg_wds_status_check() {
    struct sysinfo info;
	//获取当前时间
	sysinfo(&info);

    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
	struct dev_multi_info *last_p = NULL;

    while(p) {
        if (info.uptime > p->time_update) {
            if ((info.uptime - p->time_update) > 2*60) {
                DEBUG("sn %s unkonw %s time_update %d info.uptime %d ",p->sn,p->ssid,p->time_update,info.uptime);
				//非本机链表
				if (strcmp(p->sn,rg_dev_info_t.sn) != 0) {
                    g_dev_multi_info_cnt--;
					if (p == rg_wds_all_info) {
						rg_wds_all_info = p->next;
						free(p);
					} else if (p->next == NULL) {
						last_p->next = NULL;
						free(p);
					} else {
						last_p->next = p->next;
						free(p);
					}
					goto end;
				}

            }
        }
		last_p = p;
        p = p->next;
    }
end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_clear_all_list(){
    pthread_mutex_lock(&mtx_rg_wds_all_info);

    struct dev_multi_info *p = rg_wds_all_info;
    struct dev_multi_info *tmp;
    int len = 0;
    while(p) {
        tmp = p;
        p = p->next;
        len++;
        free(tmp);
        DEBUG("free 11");
    }
    g_dev_multi_info_cnt = 0;

	rg_wds_all_info = NULL;
    DEBUG("len %d",len);
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_send_multi(unsigned long time_count_all) {
    if (time_count_all % 100 == 99) {
        rg_wds_send_all();
    }

    //每10
    if (time_count_all % (10 * 10)== 60) {
        rg_wds_status_check();
    }

    if (time_count_all % 100 == 49) {
//        rg_wds_wrt_wdsall_page();
        rg_wds_write_info_all_list();
        rg_wds_wrt_info_lite();
    }
}

char *rg_wds_get_option_vaule(char *buf,char *option,int op_len,char *value,int va_len){
    char *p = buf;
    int i = 0;
    int j;

    if (strlen(buf) < 2) {
        return NULL;
    }

    memset(option,0,op_len);
    memset(value,0,va_len);

    while(1) {
        if (p[i] == ':' || p[i] == 0) {
            break;
        }
        i++;
    }

    if (i > 0) {
        memcpy(option,p,i);
        //DEBUG("option %s,i %d",option,i);
    } else {
        goto end;
    }


    j = i;
    while(1) {
        if (p[i] == ';' || p[i] == 0 ||  p[i] == '#') {
            break;
        }
        i++;
    }
    if (i - j - 1 > 0) {
        memcpy(value,buf + j + 1,i - j - 1);
        //DEBUG("value %s,i %d",value,i - j - 1);
    } else {
        goto end;
    }

    //DEBUG("%s:%s",option,value);
    return p + i + 1;

end:
    return NULL;

}

void rg_wds_get_info_all_list(char *sn,char *option,char *value) {
    //pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    struct dev_multi_info *tmp;
    struct dev_multi_info *p1;
    struct sysinfo info;

	//获取当前时间
	sysinfo(&info);
    p1 = p;
    while (p != NULL) {
        if (strcmp(p->sn,sn) == 0) {
            if (strcmp(option,"hostname") == 0) {
                if (strcmp(value,p->host_name) != 0) {
                    memset(p->host_name,0,sizeof(p->host_name));
                    memcpy(p->host_name,value,strlen(value));
                }
            } else if (strcmp(option,"ssid") == 0) {
                if (strcmp(value,p->ssid) != 0) {
                    memset(p->ssid,0,sizeof(p->ssid));
                    memcpy(p->ssid,value,strlen(value));
                }
            } else if (strcmp(option,"sysmac") == 0) {
                if (strcmp(value,p->sys_mac) != 0) {
                    memset(p->sys_mac,0,sizeof(p->sys_mac));
                    memcpy(p->sys_mac,value,strlen(value));
                }
            } else if (strcmp(option,"model") == 0) {
                if (strcmp(value,p->dev_type) != 0) {
                    memset(p->dev_type,0,sizeof(p->dev_type));
                    memcpy(p->dev_type,value,strlen(value));
                }
            } else if (strcmp(option,"role") == 0) {
                if (strcmp(value,p->role) != 0) {
                    memset(p->role,0,sizeof(p->role));
                    memcpy(p->role,value,strlen(value));
                }
            } else if (strcmp(option,"lock") == 0) {
                if (strcmp(value,p->lock) != 0) {
                    memset(p->lock,0,sizeof(p->lock));
                    memcpy(p->lock,value,strlen(value));
                }
            } else if (strcmp(option,"athmac") == 0) {
                if (strcmp(value,p->ath_mac) != 0) {
                    memset(p->ath_mac,0,sizeof(p->ath_mac));
                    memcpy(p->ath_mac,value,strlen(value));
                }
            } else if (strcmp(option,"softversion") == 0) {
                if (strcmp(value,p->software_version) != 0) {
                    memset(p->software_version,0,sizeof(p->software_version));
                    memcpy(p->software_version,value,strlen(value));
                }
            } else if (strcmp(option,"peersn") == 0) {
                if (strcmp(value,p->peer_sn) != 0) {
                    memset(p->peer_sn,0,sizeof(p->peer_sn));
                    memcpy(p->peer_sn,value,strlen(value));
                }
            } else if (strcmp(option,"userIp") == 0) {
                if (strcmp(value,p->ipaddr) != 0) {
                    memset(p->ipaddr,0,sizeof(p->ipaddr));
                    memcpy(p->ipaddr,value,strlen(value));
                }
            } else if (strcmp(option,"onlineTime") == 0) {
                if (strcmp(value,p->time) != 0) {
                    memset(p->time,0,sizeof(p->time));
                    memcpy(p->time,value,strlen(value));
                }
            } else if (strcmp(option,"band") == 0) {
                if (strcmp(value,p->band) != 0) {
                    memset(p->band,0,sizeof(p->band));
                    memcpy(p->band,value,strlen(value));
                }
            } else if (strcmp(option,"rssi") == 0) {
                if (strcmp(value,p->rssi) != 0) {
                    memset(p->rssi,0,sizeof(p->rssi));
                    memcpy(p->rssi,value,strlen(value));
                }
            } else if (strcmp(option,"rate") == 0) {
                if (strcmp(value,p->rate) != 0) {
                    memset(p->rate,0,sizeof(p->rate));
                    memcpy(p->rate,value,strlen(value));
                }
            } else if (strcmp(option,"channel") == 0) {
                if (strcmp(value,p->channel) != 0) {
                    memset(p->channel,0,sizeof(p->channel));
                    memcpy(p->channel,value,strlen(value));
                }
            } else if (strcmp(option,"passwd") == 0) {
                if (strcmp(value,p->passwd) != 0) {
                    memset(p->passwd,0,sizeof(p->passwd));
                    memcpy(p->passwd,value,strlen(value));
                }
            } else if (strcmp(option,"channf") == 0) {
                if (strcmp(value,p->channf) != 0) {
                    memset(p->channf,0,sizeof(p->channf));
                    memcpy(p->channf,value,strlen(value));
                }
            } else if (strcmp(option,"chutil") == 0) {
                if (strcmp(value,p->chutil) != 0) {
                    memset(p->chutil,0,sizeof(p->chutil));
                    memcpy(p->chutil,value,strlen(value));
                }
            } else if (strcmp(option,"distance") == 0) {
                if (strcmp(value,p->wds_distance) != 0) {
                    memset(p->wds_distance,0,sizeof(p->wds_distance));
                    memcpy(p->wds_distance,value,strlen(value));
                }
            } else if (strcmp(option,"txpower") == 0) {
                if (strcmp(value,p->wds_txpower) != 0) {
                    memset(p->wds_txpower,0,sizeof(p->wds_txpower));
                    memcpy(p->wds_txpower,value,strlen(value));
                }
            } else if (strcmp(option,"phymode") == 0) {
                if (strcmp(value,p->phymode) != 0) {
                    memset(p->phymode,0,sizeof(p->phymode));
                    memcpy(p->phymode,value,strlen(value));
                }
            } else if (strcmp(option,"netmask") == 0) {
                if (strcmp(value,p->netmask) != 0) {
                    memset(p->netmask,0,sizeof(p->netmask));
                    memcpy(p->netmask,value,strlen(value));
                }
            } else if (strcmp(option,"cwmp") == 0) {
                if (strcmp(value,p->cwmp) != 0) {
                    memset(p->cwmp,0,sizeof(p->cwmp));
                    memcpy(p->cwmp,value,strlen(value));
                }
            } else if (strcmp(option,"lan1speed") == 0) {
                if (strcmp(value,p->lan1speed) != 0) {
                    memset(p->lan1speed,0,sizeof(p->lan1speed));
                    memcpy(p->lan1speed,value,strlen(value));
                }
            } else if (strcmp(option,"lan1link") == 0) {
                if (strcmp(value,p->lan1link) != 0) {
                    memset(p->lan1link,0,sizeof(p->lan1link));
                    memcpy(p->lan1link,value,strlen(value));
                }
            } else if (strcmp(option,"lan1duplex") == 0) {
                if (strcmp(value,p->lan1duplex) != 0) {
                    memset(p->lan1duplex,0,sizeof(p->lan1duplex));
                    memcpy(p->lan1duplex,value,strlen(value));
                }
            } else if (strcmp(option,"lan2speed") == 0) {
                if (strcmp(value,p->lan2speed) != 0) {
                    memset(p->lan2speed,0,sizeof(p->lan2speed));
                    memcpy(p->lan2speed,value,strlen(value));
                }
            } else if (strcmp(option,"lan2link") == 0) {
                if (strcmp(value,p->lan2link) != 0) {
                    memset(p->lan2link,0,sizeof(p->lan2link));
                    memcpy(p->lan2link,value,strlen(value));
                }
            } else if (strcmp(option,"lan2duplex") == 0) {
                if (strcmp(value,p->lan2duplex) != 0) {
                    memset(p->lan2duplex,0,sizeof(p->lan2duplex));
                    memcpy(p->lan2duplex,value,strlen(value));
                }
            } else if (strcmp(option,"onlinestatus") == 0) {
                if (strcmp(value,p->onlinestatus) != 0) {
                    memset(p->onlinestatus,0,sizeof(p->onlinestatus));
                    memcpy(p->onlinestatus,value,strlen(value));
                }
            } else if (strcmp(option,"rx_rate") == 0) {
                if (strcmp(value,p->rx_rate) != 0) {
                    memset(p->rx_rate,0,sizeof(p->rx_rate));
                    memcpy(p->rx_rate,value,strlen(value));
                }
            } else if (strcmp(option,"tx_rate") == 0) {
                if (strcmp(value,p->tx_rate) != 0) {
                    memset(p->tx_rate,0,sizeof(p->tx_rate));
                    memcpy(p->tx_rate,value,strlen(value));
                }
            } else if (strcmp(option,"peermac") == 0) {
                if (strcmp(value,p->peermac) != 0) {
                    memset(p->peermac,0,sizeof(p->peermac));
                    memcpy(p->peermac,value,strlen(value));
                }
            } else if (strcmp(option,"hardversion") == 0) {
                if (strcmp(value,p->hardware_version) != 0) {
                    memset(p->hardware_version,0,sizeof(p->hardware_version));
                    memcpy(p->hardware_version,value,strlen(value));
                }
            } else if (strcmp(option,"rx_speed") == 0) {
                if (strcmp(value,p->rx_speed) != 0) {
                    memset(p->rx_speed,0,sizeof(p->rx_speed));
                    memcpy(p->rx_speed,value,strlen(value));
                }
            } else if (strcmp(option,"tx_speed") == 0) {
                if (strcmp(value,p->tx_speed) != 0) {
                    memset(p->tx_speed,0,sizeof(p->tx_speed));
                    memcpy(p->tx_speed,value,strlen(value));
                }
            } else if (strcmp(option,"tx_speed_a") == 0) {
                if (strcmp(value,p->tx_speed_a) != 0) {
                    memset(p->tx_speed_a,0,sizeof(p->tx_speed_a));
                    memcpy(p->tx_speed_a,value,strlen(value));
                }
            } else if (strcmp(option,"rx_speed_a") == 0) {
                if (strcmp(value,p->rx_speed_a) != 0) {
                    memset(p->rx_speed_a,0,sizeof(p->rx_speed_a));
                    memcpy(p->rx_speed_a,value,strlen(value));
                }
            } else if (strcmp(option,"rssi_a") == 0) {
                if (strcmp(value,p->rssi_a) != 0) {
                    memset(p->rssi_a,0,sizeof(p->rssi_a));
                    memcpy(p->rssi_a,value,strlen(value));
                }
            } else if (strcmp(option,"chutil_a") == 0) {
                if (strcmp(value,p->chutil_a) != 0) {
                    memset(p->chutil_a,0,sizeof(p->chutil_a));
                    memcpy(p->chutil_a,value,strlen(value));
                }
            } else if (strcmp(option,"pingTime") == 0) {
                if (strcmp(value,p->pingTime) != 0) {
                    memset(p->pingTime,0,sizeof(p->pingTime));
                    memcpy(p->pingTime,value,strlen(value));
                }
            } else if (strcmp(option,"connectTime") == 0) {
                if (strcmp(value,p->connectTime) != 0) {
                    memset(p->connectTime,0,sizeof(p->connectTime));
                    memcpy(p->connectTime,value,strlen(value));
                }
            } else if (strcmp(option,"networkId") == 0) {
                if (strcmp(value,p->networkid) != 0) {
                    memset(p->networkid,0,sizeof(p->networkid));
                    memcpy(p->networkid, value, sizeof(p->networkid) - 1);
                }
            } else if (strcmp(option,"networkName") == 0) {
                if (strcmp(value,p->networkname) != 0) {
                    memset(p->networkname,0,sizeof(p->networkname));
                    memcpy(p->networkname, value, sizeof(p->networkname) - 1);
                }
            }

            p->time_update = info.uptime;
            goto end;
        }
        p1 = p;
        p = p->next;
    }

    if (p == NULL && g_dev_multi_info_cnt < DEV_MULTI_MAXCNT) {
        tmp = malloc(sizeof(struct dev_multi_info));
        DEBUG("create %s ",sn);
        if (tmp != NULL) {
            memset(tmp,0,sizeof(struct dev_multi_info));
            memcpy(tmp->sn,sn,strlen(sn));
            tmp->time_update = info.uptime;
            p = tmp;
            g_dev_multi_info_cnt++;
        }

        if (rg_wds_all_info == NULL) {
            rg_wds_all_info = tmp;
        } else {
            p1->next = tmp;
        }
    }
end:
    //pthread_mutex_unlock(&mtx_rg_wds_all_info);
    return;
}

void rg_wds_show_info_all_list() {
    return;
    struct dev_multi_info *p = rg_wds_all_info;
    while (p != NULL) {
        DEBUG("sn:%s",p->sn);
        DEBUG("sys_mac:%s",p->sys_mac);
        DEBUG("ath_mac:%s",p->ath_mac);
        DEBUG("lock:%s",p->lock);
        DEBUG("role:%s",p->role);
        DEBUG("ssid:%s",p->ssid);
        DEBUG("dev_type:%s",p->dev_type);
        DEBUG("software_version:%s",p->software_version);
        DEBUG("peer_sn:%s",p->peer_sn);
        DEBUG("ip:%s",p->ipaddr);
        p = p->next;
    }
}

struct dev_multi_info * rg_wds_find_peer(struct dev_multi_info *p,char *peer_sn) {
    while (p) {
        if ((strcmp(peer_sn,p->ath_mac) == 0 || strcmp(peer_sn,p->peermac) == 0) && p->flag == 0) {
            p->flag = 1;
            return p;
        }
        p = p->next;
    }
    return p;
}

void rg_wds_json_add_item(struct dev_multi_info *p,json_object *item) {
    json_object_object_add(item,"sn", json_object_new_string(p->sn));
    json_object_object_add(item,"mac", json_object_new_string(p->sys_mac));
    json_object_object_add(item,"ssid", json_object_new_string(p->ssid));
    json_object_object_add(item,"softversion", json_object_new_string(p->software_version));
    json_object_object_add(item,"role", json_object_new_string(p->role));
    json_object_object_add(item,"userIp", json_object_new_string(p->ipaddr));
    json_object_object_add(item,"peersn", json_object_new_string(p->peer_sn));
    json_object_object_add(item,"userIp", json_object_new_string(p->ipaddr));
    json_object_object_add(item,"onlineTime", json_object_new_string(p->time));
    json_object_object_add(item,"band", json_object_new_string(p->band));
    json_object_object_add(item,"rssi", json_object_new_string(p->rssi));
    json_object_object_add(item,"rssi_a", json_object_new_string(p->rssi_a));
    json_object_object_add(item,"rxrate", json_object_new_string(p->rate));
    json_object_object_add(item,"channel", json_object_new_string(p->channel));
    json_object_object_add(item,"passwd", json_object_new_string(p->passwd));
    json_object_object_add(item,"channf", json_object_new_string(p->channf));
    json_object_object_add(item,"chutil", json_object_new_string(p->chutil));
    json_object_object_add(item,"chutil_a", json_object_new_string(p->chutil_a));
    json_object_object_add(item,"distance", json_object_new_string(p->wds_distance));
    json_object_object_add(item,"txpower", json_object_new_string(p->wds_txpower));
    json_object_object_add(item,"phymode", json_object_new_string(p->phymode));
    json_object_object_add(item,"netmask", json_object_new_string(p->netmask));
    json_object_object_add(item,"lock", json_object_new_string(p->lock));
    json_object_object_add(item,"cwmp", json_object_new_string(p->cwmp));
    json_object_object_add(item,"lan1speed", json_object_new_string(p->lan1speed));
    json_object_object_add(item,"lan1link", json_object_new_string(p->lan1link));
    json_object_object_add(item,"lan1duplex", json_object_new_string(p->lan1duplex));
    json_object_object_add(item,"lan2speed", json_object_new_string(p->lan2speed));
    json_object_object_add(item,"lan2link", json_object_new_string(p->lan2link));
    json_object_object_add(item,"lan2duplex", json_object_new_string(p->lan2duplex));
    json_object_object_add(item,"hostname", json_object_new_string(p->host_name));
    json_object_object_add(item,"onlinestatus", json_object_new_string(p->onlinestatus));
    json_object_object_add(item,"rx_rate", json_object_new_string(p->rx_rate));
    json_object_object_add(item,"tx_rate", json_object_new_string(p->tx_rate));
    json_object_object_add(item,"dev_type", json_object_new_string(p->dev_type));
    json_object_object_add(item,"peermac", json_object_new_string(p->peermac));
    json_object_object_add(item,"athmac", json_object_new_string(p->ath_mac));
    json_object_object_add(item,"hardversion", json_object_new_string(p->hardware_version));
    json_object_object_add(item,"rx_speed", json_object_new_string(p->rx_speed));
    json_object_object_add(item,"tx_speed", json_object_new_string(p->tx_speed));
    json_object_object_add(item,"rx_speed_a", json_object_new_string(p->rx_speed_a));
    json_object_object_add(item,"tx_speed_a", json_object_new_string(p->tx_speed_a));
    json_object_object_add(item,"pingTime", json_object_new_string(p->pingTime));
    json_object_object_add(item,"connectTime", json_object_new_string(p->connectTime));

    json_object_object_add(item,"networkId", json_object_new_string(p->networkid));
    json_object_object_add(item,"networkName", json_object_new_string(p->networkname));

}

void rg_wds_json_add_lite_item(struct dev_multi_info *p,json_object *item) {
    json_object_object_add(item,"sn", json_object_new_string(p->sn));
    json_object_object_add(item,"mac", json_object_new_string(p->sys_mac));
    json_object_object_add(item,"rl", json_object_new_string(p->role));
    json_object_object_add(item,"dt", json_object_new_string(p->dev_type));
    json_object_object_add(item,"nid", json_object_new_string(p->networkid));
    json_object_object_add(item,"nn", json_object_new_string(p->networkname));
    json_object_object_add(item,"rs", json_object_new_string(p->rssi));
    json_object_object_add(item,"ts", json_object_new_string(p->tx_speed));
    json_object_object_add(item,"hn", json_object_new_string(p->host_name));
    json_object_object_add(item,"ct", json_object_new_string(p->connectTime));
    json_object_object_add(item,"ch", json_object_new_string(p->channel));
}

static unsigned int rg_wds_get_page_size(void)
{
    struct dev_multi_info *p;
    unsigned int page_group;

    p = rg_wds_all_info;
    if (!p) {
        return 0;
    }

    page_group = 0;
    while (p) {
        /* cpe offline */
        if (strcmp("cpe", p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            } else {
                goto loop2;
            }
        }
loop1:
        page_group++;
loop2:
        p = p->next;
    }

    return page_group;
}

void rg_wds_wrt_wdsall_page(void)
{
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    json_object *section, *section_1, *file_1, *file_2, *item_3, *item_4;
    unsigned int page_total, group_total, page_size, file_num;
    unsigned int total = 0;
    unsigned int wds_total[4];
    char wds_file_name[128], flag_free;
    const char *str;
    int fd;
    struct dev_multi_info *tmp = NULL;

    system("rm -rf /tmp/wds_all_page*.json");

    file_num = 0;
    group_total = rg_wds_get_page_size();
    if (group_total == 0) {
        pthread_mutex_unlock(&mtx_rg_wds_all_info);
        return;
    }

    page_size = group_total;
    file_1 = json_object_new_object();
    section = json_object_new_array();
    while (p) {
        total++;
        file_2 = json_object_new_object();
        section_1 = json_object_new_array();
        item_3 = json_object_new_object();
        flag_free = 0;
        if (p->flag == 0) {
            p->flag = 1;
        } else {
            flag_free = 1;
            goto loop2;
        }
        /* cpe offline */
        if (strcmp("cpe", p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            }
        }
loop1:
        tmp = rg_wds_all_info;
        while (tmp) {
            if (strcmp("ap", p->role) == 0) {
                tmp = rg_wds_find_peer(tmp, p->ath_mac);
            } else {
                tmp = rg_wds_find_peer(tmp, p->peermac);
            }
            if (tmp != NULL) {
                json_object *item_2 = json_object_new_object();
                rg_wds_json_add_item(tmp, item_2);
                 json_object_array_add(section_1, item_2);
                tmp = tmp->next;
            }
        }
        rg_wds_json_add_item(p, item_3);
        json_object_array_add(section_1, item_3);
        json_object_object_add(file_2, "list_pair", section_1);
        json_object_array_add(section, file_2);
        page_total++;
        page_size--;

        if (page_total % LIST_ALL_PAGE_SIZE == 0
            || (page_size < LIST_ALL_PAGE_SIZE && page_size % LIST_ALL_PAGE_SIZE == 0)) {
            file_num++;
            memset(wds_total, 0, sizeof(wds_total));
            snprintf(wds_total, sizeof(wds_total), "%u", group_total);
            json_object_object_add(file_1, "total", json_object_new_string(wds_total));
            json_object_object_add(file_1, "list_all", section);
            str = json_object_to_json_string(file_1);
            memset(wds_file_name, 0, sizeof(wds_file_name));
            snprintf(wds_file_name, sizeof(wds_file_name), "/tmp/wds_all_page_%d.json", file_num);
            rg_wds_misc_clear_file(wds_file_name);
            fd = open(wds_file_name, O_CREAT | O_RDWR, 0644);
            if (fd) {
                write(fd, str, strlen(str));
                close(fd);
            }

            json_object_put(file_1);

            file_1 = json_object_new_object();
            section = json_object_new_array();
        }
loop2:
        if (flag_free) {
            json_object_put(item_3);
            json_object_put(section_1);
            json_object_put(file_2);
        }
        p = p->next;
    }

    p = rg_wds_all_info;
    while (p) {
        p->flag = 0;
        p = p->next;
    }
    json_object_put(section);
    json_object_put(file_1);

end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
    return;
}

void rg_wds_write_info_all_list() {
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    unsigned int total = 0;
    unsigned int wds_total[4];

	if (p == NULL) {
		rg_wds_misc_clear_file("/tmp/wds_info_all.json");
		goto end;
	}

	json_object *file_1 = json_object_new_object();
    json_object *section_2 = json_object_new_array();
    char flag_free = 0;

    while(p != NULL) {
        json_object *section_1 = json_object_new_array();
        json_object *file_2 = json_object_new_object();
        json_object *item_3 = json_object_new_object();
        flag_free = 0;
        if (p->flag == 0) {
            p->flag = 1;
        } else {
            flag_free = 1;
            goto loop2;
        }

        //CPE有可能没有桥接成功的情况
        if (strcmp("cpe",p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            }
        }

        struct dev_multi_info *tmp = rg_wds_all_info;
        while (tmp) {
            if (strcmp("ap",p->role) == 0) {
                tmp = rg_wds_find_peer(tmp,p->ath_mac);
            } else {
                tmp = rg_wds_find_peer(tmp,p->peermac);
            }
            if (tmp != NULL) {
                json_object *item_2 = json_object_new_object();
                rg_wds_json_add_item(tmp,item_2);
                json_object_array_add(section_1, item_2);
                tmp = tmp->next;
            }
        }
loop1:
        rg_wds_json_add_item(p,item_3);
        json_object_array_add(section_1, item_3);
        json_object_object_add(file_2, "list_pair", section_1);
        json_object_array_add(section_2, file_2);
loop2:
        if (flag_free) {
            json_object_put(section_1);
            json_object_put(file_2);
            json_object_put(item_3);
        }
        p = p->next;
    }

    p = rg_wds_all_info;
    while (p) {
        p->flag = 0;
        p = p->next;
        total++;
    }

    json_object_object_add(file_1, "list_all", section_2);
    memset(wds_total, 0, sizeof(wds_total));
    snprintf(wds_total, sizeof(wds_total), "%u", total);
    json_object_object_add(file_1, "total", json_object_new_string(wds_total));

    int fd;
    const char *str = json_object_to_json_string(file_1);
    rg_wds_misc_clear_file("/tmp/wds_info_all.json");
	fd = open("/tmp/wds_info_all.json", O_CREAT | O_RDWR,0644);
    if (fd) {
        write(fd,str,strlen(str));
        close(fd);
    }

    json_object_put(file_1);
end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_wrt_info_lite() {
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    struct dev_multi_info *p = rg_wds_all_info;
    unsigned int total = 0;
    unsigned int wds_total[4];

	if (p == NULL) {
		rg_wds_misc_clear_file("/tmp/wds_info_lite.json");
		goto end;
	}

	json_object *file_1 = json_object_new_object();
    json_object *section_2 = json_object_new_array();
    char flag_free = 0;

    while(p != NULL) {
        json_object *section_1 = json_object_new_array();
        json_object *file_2 = json_object_new_object();
        json_object *item_3 = json_object_new_object();
        flag_free = 0;
        if (p->flag == 0) {
            p->flag = 1;
        } else {
            flag_free = 1;
            goto loop2;
        }

        //CPE有可能没有桥接成功的情况
        if (strcmp("cpe",p->role) == 0) {
            if (strlen(p->peermac) == 0) {
                goto loop1;
            }
        }

        struct dev_multi_info *tmp = rg_wds_all_info;
        while (tmp) {
            if (strcmp("ap",p->role) == 0) {
                tmp = rg_wds_find_peer(tmp,p->ath_mac);
            } else {
                tmp = rg_wds_find_peer(tmp,p->peermac);
            }
            if (tmp != NULL) {
                json_object *item_2 = json_object_new_object();
                rg_wds_json_add_lite_item(tmp, item_2);
                json_object_array_add(section_1, item_2);
                tmp = tmp->next;
            }
        }
loop1:

        rg_wds_json_add_lite_item(p,item_3);
        json_object_array_add(section_1, item_3);
        json_object_object_add(file_2, "list_pair", section_1);
        json_object_array_add(section_2, file_2);

loop2:
        if (flag_free) {
            json_object_put(section_1);
            json_object_put(file_2);
            json_object_put(item_3);
        }
        p = p->next;
    }

    p = rg_wds_all_info;
    while (p) {
        p->flag = 0;
        p = p->next;
        total++;
    }

    json_object_object_add(file_1, "list_all", section_2);
    memset(wds_total, 0, sizeof(wds_total));
    snprintf(wds_total, sizeof(wds_total), "%u", total);
    json_object_object_add(file_1, "total", json_object_new_string(wds_total));

    int fd;
    const char *str = json_object_to_json_string(file_1);
    rg_wds_misc_clear_file("/tmp/wds_info_lite.json");
    fd = open("/tmp/wds_info_lite.json", O_CREAT | O_RDWR,0644);
    if (fd) {
        write(fd, str, strlen(str));
        close(fd);
    }

    json_object_put(file_1);
end:
    pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_get_info_multi(char *str) {
    char *p = str;
    char option[100];
    char value[200];
    char sn[30];


    p = p + 1;
    memset(sn,0,sizeof(sn));
    pthread_mutex_lock(&mtx_rg_wds_all_info);
    while (p != NULL) {
        p = rg_wds_get_option_vaule(p,option,sizeof(option),value,sizeof(value));
        if (memcmp(option,"sn",strlen("sn")) == 0) {
            memset(sn,0,sizeof(sn));
            memcpy(sn,value,strlen(value));
        }

        if (strlen(sn) != 0 && p != NULL) {
            rg_wds_get_info_all_list(sn,option,value);
        }
    }
	pthread_mutex_unlock(&mtx_rg_wds_all_info);
}

void rg_wds_message_dev_process(char *str) {
    char *p = str;
    char buf[2000];

    memset(buf,0,sizeof(buf));

    p = rg_wds_cmp_str(p,buf);

    //合法性检查
    if (rg_wds_check_1(buf) == 0) {
        return;
    }

    memset(buf,0,sizeof(buf));
    p = rg_wds_cmp_str(p,buf);

    switch (rg_wds_type_process(buf)) {
        case TYPE_SET:
            rg_wds_set_process(p);
            break;
        case TYPE_GET:
            break;
        case TYPE_INFO:
            rg_wds_get_info_multi(p);
            break;
        default:
            break;
    }
}
