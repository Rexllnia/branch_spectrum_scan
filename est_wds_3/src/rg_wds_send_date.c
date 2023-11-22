#include "rg_wds.h"


//发送报文头部处理
int rg_wds_send_date_head_init(struct  mac_ip_udp_wds_packet *eth_packet_heap_p) 
{
	memset(eth_packet_heap_p,0,sizeof(struct  mac_ip_udp_wds_packet));
	eth_packet_heap_p->eth_header_date.ether_type = htons(ETHERTYPE_IP);
	memset(eth_packet_heap_p->eth_header_date.ether_dhost, 0xff, 6);	
}

//
void rg_wds_version_wds_date_head_fill(struct wds_date_head *version_date_p,char flag) {
	memset(version_date_p,0,sizeof(struct wds_date_head));
	version_date_p->role = rg_ath_info_t.role;
	version_date_p->lock = rg_gpio_info_t.gpio_lock_value;
	version_date_p->unuse = 0x55;
	version_date_p->unuse2 = 0xaa;
	memcpy(version_date_p->name,"abcd",strlen("abcd"));	
	version_date_p->sync_flag = flag;
}

unsigned short checksum(unsigned short *buf, int nword)
{
    unsigned long sum;
    for(sum = 0; nword > 0; nword--)
    {
        sum += ntohs(*buf);
        buf++;
    }
    sum = (sum>>16) + (sum&0xffff);
    sum += (sum>>16);
    return ~sum;
}

//默认全部从50001端口发出
int rg_send_raw_date(char *ifname,int data_len,unsigned char *send_msg,char *dst_char_mac)
{
	unsigned char *tmp;
	int len;
	char wds_sync_fail_count = 0;
	int ap_flag;
	unsigned char src_mac[6];
	unsigned char dst_hex_mac[6];
	unsigned char ip_head[24] = {
									0x45,0xf0,0x00,0x00,    
								    0x00,0x00,0x00,0x00,   
									0x80,17,0x00,0x00,    
									0,0,0,0,   
									0,0,0,0, 
									0xc3,0x51,0xc3,0x51
								 };
	memset(src_mac,0,sizeof(src_mac));
	if (FAIL == rg_wds_misc_get_mac(ifname,src_mac)) {
		GPIO_ERROR("rg_wds_misc_get_mac error!");
		return FAIL;
	}
    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw_fd < 0) {
		GPIO_ERROR("socket error!");
		return FAIL;
	}
	if (dst_char_mac != NULL) {
		tmp = send_msg;
		memcpy(tmp,dst_char_mac,6);
	}

    tmp = send_msg + 6;
    memcpy(tmp,src_mac,sizeof(src_mac));
    tmp = send_msg + WDS_ETH_HEAD_LEN;
    memcpy(tmp,ip_head,sizeof(ip_head));
    if(data_len % 2 == 1)
    {
        data_len++;
    }

    /* ip报文的长度 = 20字节的ip头部 + 8字节udp头部 + payload数据长度 */
    *((unsigned short *)&send_msg[16]) = htons(data_len - WDS_ETH_HEAD_LEN);
    /* udp头部长度 = 8字节udp头部长度+payload数据长度 */
    *((unsigned short *)&send_msg[WDS_ETH_HEAD_LEN + WDS_IP_HEAD_LEN + 4]) =
                                htons(data_len - WDS_ETH_HEAD_LEN - WDS_IP_HEAD_LEN);

    unsigned char pseudo_head[1500] = {
        0,  0,  0,  0,    //src_ip: 10.221.20.11
        0,  0,  0,  0,    //dst_ip: 10.221.20.10
        0x00, 17,  0x00, 0x00,    // 0,17,#--16位UDP长度--20个字节
    };
    /*  为头部中的udp长度（和真实udp长度是同一个值） */
    *((unsigned short *)&pseudo_head[10]) = htons(data_len - WDS_ETH_HEAD_LEN - WDS_IP_HEAD_LEN);
    /* 保证多次校验checksum正确，不清空会导致checksum位全零 */
    *((unsigned short *)&send_msg[40]) = htons(0);
    /*--计算udp校验和时需要加上伪头部--*/
    memcpy(pseudo_head + WDS_PSEUDO_HEAD_LEN, send_msg + WDS_ETH_HEAD_LEN + WDS_IP_HEAD_LEN,
                                                data_len - WDS_ETH_HEAD_LEN - WDS_IP_HEAD_LEN);
    /* 对IP首部进行校验 */
    *((unsigned short *)&send_msg[24]) =
                htons(checksum((unsigned short *)(send_msg + WDS_ETH_HEAD_LEN), WDS_IP_HEAD_LEN / 2));
    /* UDP数据进行校验 */
    *((unsigned short *)&send_msg[40]) =
        htons(checksum((unsigned short *)pseudo_head, (data_len - WDS_ETH_HEAD_LEN - WDS_IP_HEAD_LEN + WDS_PSEUDO_HEAD_LEN) / 2));

    struct sockaddr_ll sll;
    struct ifreq ethreq;
   
    strncpy(ethreq.ifr_name,ifname,IFNAMSIZ);
    if(-1 == ioctl(sock_raw_fd, SIOCGIFINDEX, &ethreq))
    {	
    	GPIO_DEBUG("sock_raw_fd SIOCGIFINDEX");
        perror("ioctl");
        close(sock_raw_fd);
        return FAIL;
    }
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex;

    int flags = fcntl(sock_raw_fd, F_GETFL, 0);
    fcntl(sock_raw_fd, F_SETFL, flags | O_NONBLOCK);
    
	len = sendto(sock_raw_fd, send_msg, data_len, 0 , (struct sockaddr *)&sll, sizeof(sll));
	close(sock_raw_fd);
	//dump_date(send_msg,14+20+8+len);
}

//有指定端口
int rg_send_raw_date_2(char *ifname,int date_len,unsigned char *send_msg,char *dst_char_mac)
{
	unsigned char *tmp;
	int len;
	char wds_sync_fail_count = 0;
	int ap_flag;
	//unsigned char src_mac[6];
	unsigned char dst_hex_mac[6];
    unsigned char multi_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned char ip_head[24] = {
									0x45,0xf0,0x00,0x00,    
								    0x00,0x00,0x00,0x00,   
									0x80,17,0x00,0x00,    
									0,0,0,0,   
									0,0,0,0, 
									0xc3,0x52,0xc3,0x52
								 };

    #if 0
	memset(src_mac,0,sizeof(src_mac));
	if (FAIL == rg_wds_misc_get_mac(ifname,src_mac)) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}
    #endif
    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw_fd < 0) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}
    
	if (dst_char_mac != NULL) {
		tmp = send_msg;
		memcpy(tmp,dst_char_mac,6);
	} else {
		tmp = send_msg;
        //如果地址为空，则默认为广播
		memcpy(tmp,multi_mac,6);
    }

   	tmp = send_msg + 6;
    //memcpy(tmp,src_mac,sizeof(src_mac));
    memcpy(tmp,rg_dev_info_t.sys_mac,6);
	tmp = send_msg + 14;
	memcpy(tmp,ip_head,sizeof(ip_head));
    if((len = date_len) % 2 == 1)
    {
        len++;
    }	

    *((unsigned short *)&send_msg[16]) = htons(20+8+len);
    *((unsigned short *)&send_msg[14+20+4]) = htons(8+len);

    unsigned char pseudo_head[1500] = {
		0,  0,	0,  0,	  //src_ip: 10.221.20.11
		0,  0,	0,  0,	  //dst_ip: 10.221.20.10
        0x00, 17,  0x00, 0x00,    // 0,17,#--16位UDP长度--20个字节
    };
   
    *((unsigned short *)&pseudo_head[10]) = htons(8 + len); //为头部中的udp长度（和真实udp长度是同一个值）
    memcpy(pseudo_head+12, send_msg+34, 8+len); //--计算udp校验和时需要加上伪头部--
    //对IP首部进行校验
    *((unsigned short *)&send_msg[24]) = htons(checksum((unsigned short *)(send_msg+14),20/2));
	//6.--对UDP数据进行校验--
    *((unsigned short *)&send_msg[40]) = htons(checksum((unsigned short *)pseudo_head,(12+8+len)/2));

    struct sockaddr_ll sll;
    struct ifreq ethreq;
   
    strncpy(ethreq.ifr_name,ifname,IFNAMSIZ);
    if(-1 == ioctl(sock_raw_fd, SIOCGIFINDEX, &ethreq))
    {
        perror("ioctl");
        close(sock_raw_fd);
        return FAIL;
    }
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex;

    int flags = fcntl(sock_raw_fd, F_GETFL, 0);
    fcntl(sock_raw_fd, F_SETFL, flags | O_NONBLOCK);
    
	len = sendto(sock_raw_fd, send_msg, 14+20+8+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
	close(sock_raw_fd);
	//dump_date(send_msg,14+20+8+len);
}


//有指定端口
int rg_send_raw_date_3(char *ifname,int date_len,unsigned char *send_msg,char *dst_char_mac,unsigned char flag ,unsigned char match)
{
	unsigned char *tmp;
	int len;
	char wds_sync_fail_count = 0;
	int ap_flag;
	//unsigned char src_mac[6];
	unsigned char dst_hex_mac[6];
    unsigned char multi_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned char ip_head[24] = {
									0x45,0xf0,0x00,0x00,    
								    0x00,0x00,0x00,0x00,   
									0x80,17,0x00,0x00,    
									0,0,0,0,   
									0,0,0,0, 
									0xc3,0x53,flag,match
								 };

    #if 0
	memset(src_mac,0,sizeof(src_mac));
	if (FAIL == rg_wds_misc_get_mac(ifname,src_mac)) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}
    #endif
    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw_fd < 0) {
		printf("%s %d error \n",__func__,__LINE__);
		return FAIL;
	}

	if (dst_char_mac != NULL) {
		tmp = send_msg;
		memcpy(tmp,dst_char_mac,6);
	} else {
		tmp = send_msg;
        //如果地址为空，则默认为广播
		memcpy(tmp,multi_mac,6);
    }

   	tmp = send_msg + 6;
	//memcpy(tmp,src_mac,sizeof(src_mac));
    memcpy(tmp,rg_dev_info_t.sys_mac,6);
	tmp = send_msg + 14;
	memcpy(tmp,ip_head,sizeof(ip_head));
    if((len = date_len) % 2 == 1)
    {
        len++;
    }	

    *((unsigned short *)&send_msg[16]) = htons(20+8+len);
    *((unsigned short *)&send_msg[14+20+4]) = htons(8+len);

    unsigned char pseudo_head[1500] = {
		0,  0,	0,  0,	  //src_ip: 10.221.20.11
		0,  0,	0,  0,	  //dst_ip: 10.221.20.10
        0x00, 17,  0x00, 0x00,    // 0,17,#--16位UDP长度--20个字节
    };
   
    *((unsigned short *)&pseudo_head[10]) = htons(8 + len); //为头部中的udp长度（和真实udp长度是同一个值）
    memcpy(pseudo_head+12, send_msg+34, 8+len); //--计算udp校验和时需要加上伪头部--
    //对IP首部进行校验
    *((unsigned short *)&send_msg[24]) = htons(checksum((unsigned short *)(send_msg+14),20/2));
	//6.--对UDP数据进行校验--
    *((unsigned short *)&send_msg[40]) = htons(checksum((unsigned short *)pseudo_head,(12+8+len)/2));

    struct sockaddr_ll sll;
    struct ifreq ethreq;
   
    strncpy(ethreq.ifr_name,ifname,IFNAMSIZ);
    if(-1 == ioctl(sock_raw_fd, SIOCGIFINDEX, &ethreq))
    {
        perror("ioctl");
        close(sock_raw_fd);
        return FAIL;
    }
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex;

    int flags = fcntl(sock_raw_fd, F_GETFL, 0);
    fcntl(sock_raw_fd, F_SETFL, flags | O_NONBLOCK);
    
	len = sendto(sock_raw_fd, send_msg, 14+20+8+len, 0 , (struct sockaddr *)&sll, sizeof(sll));
	close(sock_raw_fd);
	//dump_date(send_msg,14+20+8+len);
}

