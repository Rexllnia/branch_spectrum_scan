#include "rg_wds.h"

void rg_get_packet_func(const u_char * packet)
{
    struct mac_ip_udp_wds_packet *mac_all_date;
	struct wds_date_head *wds_receve;
	u_int16_t len;

	//过滤本机
	if (memcmp(rg_ath_info_t.root_mac_hex,packet + 6,6) == 0) {
		return;
	}

    pthread_mutex_lock(&rg_pair_mtx);
    /* 设置ssid前进行二层、三层、四层、保活数据位、以及桥接关联等情况来判断置上version_flag */
    if (rg_wds_check_all_packet_validity(packet) == -1) {
        pthread_mutex_unlock(&rg_pair_mtx);
        return;
    }
    pthread_mutex_unlock(&rg_pair_mtx);

    rg_wds_lock_status_update(packet);

    len = *((unsigned short *)&packet[16]) - 20 - 8 - sizeof(struct mac_ip_udp_wds_packet);
    wds_receve = (struct wds_packet *)((u_char *)packet + 44);
    switch (wds_receve->sync_flag) {
        case SYNC_BEGIN:
        case SYNC_CLEAR:
        case SYNC_END:
            rg_wds_get_sync_led_date((u_char *)packet + 44);
            break;
        case SYNC_KEEP_LIVE:
            rg_wds_get_keep_date((u_char *)packet,len);
            break;
        case SYNC_VERSION:
            rg_wds_version_get((u_char *)packet,len);
            break;
        case SYNC_LOCK:
            rg_wds_get_lock_cpe((u_char *)packet,len);
            break;
        case SYNC_SOFTWARE_VERSION:
            rg_wds_get_softversion((u_char *)packet,len);
            break;
        case SYNC_SOFTWARE_UPDATE:
            rg_wds_get_update_cmd((u_char *)packet,len);
            break;
        default:
            DEBUG("物是人非事事休，欲语泪先流");
            break;
    }
}

void rg_get_packet_func_2(const u_char * packet) {
    struct mac_ip_udp_wds_packet *mac_all_date;
	u_int16_t len;
    char *p;

    p = (struct wds_packet *)((u_char *)packet + 44);
    //字符串合格性校验
    if (p[0] != '#' && p[strlen(p) - 1] != '#') {
        return;
    }

    rg_wds_message_dev_process(p);
}


int rg_wds_revece_pactek_init()
{
    int sock,n_read,proto;
    #define BUFFER_MAX 2048
    char buffer[BUFFER_MAX];
    char  *ethhead, *iphead, *tcphead,*udphead, *icmphead, *p;

begin:
    if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        printf("create socket error\n");
        sleep(3);
        goto begin;
    }


    while(1)
    {
        memset(buffer,0,sizeof(buffer));
        n_read = recvfrom(sock, buffer, BUFFER_MAX, 0, NULL, NULL);
           /*
           14   6(dest)+6(source)+2(type or length)
           +
           20   ip header
           +
           8   icmp,tcp or udp header
           = 42
           */
        if(n_read < 42)
        {
            fprintf(stdout, "Incomplete header, packet corrupt\n");
            continue;
        }

        ethhead = buffer;
        p = ethhead;
        int n = 0XFF;

        iphead = ethhead + 14;
        p = iphead + 12;

        proto = (iphead + 9)[0];
        p = iphead + 20;
        if (proto == IPPROTO_UDP && ((p[0]<<8)&0XFF00 | p[1]&0XFF) == 50001) {
            rg_get_packet_func(buffer);
        } else if (proto == IPPROTO_UDP && ((p[0]<<8)&0XFF00 | p[1]&0XFF) == 50002) {
            rg_get_packet_func_2(buffer);
        }
    }
}
