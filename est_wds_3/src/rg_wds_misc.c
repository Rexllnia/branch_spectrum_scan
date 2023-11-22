#include "rg_wds.h"

char rg_wds_misc_read_file(char *name,char *buf,char len) {
	int fd;

	memset(buf,0,len);
	fd = open(name, O_RDONLY);
	if (fd > 0) {
		 read(fd,buf,len);
		 close(fd);
         if (buf[strlen(buf) - 1] == '\n') {
            buf[strlen(buf) - 1] = 0;
         }
		 return SUCESS;
	}
	return FAIL;
}

char rg_wds_misc_write_file(char *name,char *buf,char len) {
	int fd;
    char tmp[100];

	memset(tmp,0,sizeof(tmp));
	fd = open(name,O_RDWR|O_CREAT);
	if (fd > 0) {
		 read(fd,tmp,sizeof(tmp) - 1);
	} else {
        goto end;
    }

    if (strcmp(buf,tmp) == 0) {
        goto end;
    } else {
        // д֮ǰ�����
		/* ����ļ� */
		ftruncate(fd,0);
		/* ���������ļ�ƫ���� */
		lseek(fd,0,SEEK_SET);
        write(fd,buf,len);
    }

end:
    close(fd);
}



u_int32_t rg_wds_misc_get_iface_netmask(char *ifname,char *buf)
{
    int sock_netmask;
    char netmask_addr[50];

    struct ifreq ifr_mask;
    struct sockaddr_in *net_mask;

    sock_netmask = socket(AF_INET,SOCK_STREAM,0);
    if(sock_netmask == -1) {
        perror("create socket failture...GetLocalNetMask/n");
        return 0;
    }

    memset(&ifr_mask, 0, sizeof(ifr_mask));
    strncpy(ifr_mask.ifr_name, ifname, sizeof(ifr_mask.ifr_name )-1);

    if((ioctl( sock_netmask,SIOCGIFNETMASK,&ifr_mask))< 0)
    {
        printf("mac ioctl error/n");
        close(sock_netmask);
        return 0;
    }

    net_mask = ( struct sockaddr_in * )&( ifr_mask.ifr_netmask );
    strcpy(netmask_addr,inet_ntoa( net_mask -> sin_addr));

    strcpy(buf,netmask_addr);
    close(sock_netmask);
    return 0;
}


u_int32_t rg_wds_misc_get_iface_ip(const char *ifname)
{
	struct ifreq if_data;
	struct in_addr in;
	char *ip_str;
	char buf[50];
	int sockd;
	u_int32_t ip;

	/* Create a socket */
	if ((sockd = socket (AF_INET, SOCK_PACKET, htons(0x8086))) < 0) {
		return 0;
	}

	/* Get IP of internal interface */
	strcpy (if_data.ifr_name, ifname);

	/* Get the IP address */
	if (ioctl (sockd, SIOCGIFADDR, &if_data) < 0) {
        close(sockd);
		return 0;
	}
	memcpy ((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
	in.s_addr = ip;

	ip_str = inet_ntoa(in);

	memset(buf,0,sizeof(buf));
	memcpy(buf,ip_str,strlen(ip_str));
	GPIO_DEBUG("ip_str:%s", buf);
	close(sockd);
	return ip;
}


//��IP��ַת��Ϊ�ַ�������
u_int32_t rg_wds_misc_get_iface_ip_str(int ip,char *buf,char len)
{
	struct in_addr in;

	memset(buf,0,len);
	in.s_addr = ip;
	memcpy(buf,inet_ntoa(in),strlen(inet_ntoa(in)));
	GPIO_DEBUG("IP ADDRESS %s",buf);
}


int rg_wds_misc_load_wireless_uci_config(char *type,char *name,char *option_name,char *buf,int len)
{
	unsigned char tmp[100];
	FILE *p;
	int i;

	memset(tmp,0,sizeof(tmp));
	sprintf(tmp,"uci -q get wireless.@wifi-iface[0].%s",option_name);
	if((p = popen(tmp, "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return;
	}

	fread(buf,sizeof(char),len,p);
	for (i = 0;i < len;i++) {
		if (buf[i] == '\n') {
			buf[i] = 0;
		}
	}

	pclose(p);
}

int rg_wds_misc_set_wireless_uci_config(char *type,char *name,char *option_name,char *option_value,char attribute)
{
	unsigned char buf[100];

	memset(buf,0,sizeof(buf));

	//GPIO_DEBUG("%s",buf);
	if (strlen(option_value) == 0) {
		sprintf(buf,"uci -q delete wireless.@wifi-iface[0].%s",option_name);
		GPIO_DEBUG("%s",buf);
		system(buf);
	} else {
		if (attribute == UCI_ATTRI_OPTION) {
			sprintf(buf,"uci set wireless.@wifi-iface[0].%s=%s",option_name,option_value);
			GPIO_DEBUG("%s",buf);
			system(buf);
		} else if (attribute == UCI_ATTRI_LIST) {
			sprintf(buf,"uci add_list wireless.@wifi-iface[0].%s=%s",option_name,option_value);
			GPIO_DEBUG("%s",buf);
			system(buf);
		}
	}
	system("uci commit wireless");
}

char  rg_wds_misc_get_uci_option(char *cmd,char *buf,char len) {
	FILE *p;
	int i;
	if((p = popen(cmd, "r")) == NULL) {
		GPIO_ERROR("popen '%s' fail/n", cmd);
		return FAIL;
	}
	memset(buf,0,len);
	fread(buf,sizeof(char),len - 1,p);

    if (strlen(buf) <= 0) {
        goto end;
    }

	for (i = 0;i < len;i++) {
		if (buf[i] == '\n') {
			buf[i] = 0;
		}
	}

end:
	pclose(p);
	return SUCESS;
}

char rg_wds_misc_cmd(char *cmd,char *buf,char len) {
	FILE *p;
	int i;
	if((p = popen(cmd, "r")) == NULL) {
		printf("%s %d cmd %s fail\n",__func__,__LINE__,cmd);
		return FAIL;
	}

	memset(buf,0,len);
	fread(buf,sizeof(char),len - 1,p);
	for (i = 0;i < len;i++) {
		if (buf[i] == '\n') {
			buf[i] = 0;
		}
	}

	pclose(p);
	return SUCESS;
}

char  rg_wds_misc_exe_shell_cmd(char *cmd,char *buf,char len) {
	FILE *p;
	int i;
	if((p = popen(cmd, "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
		return FAIL;
	}
	memset(buf,0,len);
	fread(buf,sizeof(char),len - 1,p);
	for (i = 0;i < len;i++) {
		if (buf[i] == '\n') {
			buf[i] = 0;
		}
	}

	pclose(p);
	return SUCESS;
}

//��ȡ��ǰ mac��ַ
int rg_wds_misc_get_mac(char *ifname,unsigned char *mac)
{
    int  sockfd;
    struct sockaddr_in  sin;
    struct ifreq ifr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
	    perror("socket error");
		return FAIL;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);      //Interface name

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {  //SIOCGIFHWADDR ��ȡhardware address
		memset(mac,0,6);
	    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	    close(sockfd);
	    return SUCESS;
	}
	GPIO_DEBUG("get mac fail");
	close(sockfd);
	return FAIL;
}

void dump_date(unsigned char *buf,int len) {
	int i;
	for(i=0; i<len; ++i)
	{
	  printf(" %02x", buf[i]);
	  if((i + 1) % 16 == 0)
	  {
		printf("\n");
	  }
	}
	printf("\n");
}

int rg_wds_misc_set_uci_config(char *cmd)
{
	system(cmd);
	system("uci commit wireless");
}

int rg_wds_misc_clear_file(char * file_name) {
	int fd;

	/* ��һ���ļ� */
	fd = open(file_name,O_RDWR);
	if(fd > 0) {
		/* ����ļ� */
		ftruncate(fd,0);
		/* ���������ļ�ƫ���� */
		lseek(fd,0,SEEK_SET);
		close(fd);
		return 0;
	}
	return -1;
}

static unsigned char switch_char_2_hex(unsigned char chStr)
{
    if (chStr >= '0' && chStr <= '9')
    {
    	//GPIO_DEBUG("chStr %c",chStr);
        return (chStr - '0');
    }
    else if (chStr >= 'A' && chStr <= 'f')
    {
    	//GPIO_DEBUG("chStr %c",chStr);
        return (chStr - 'A' + 10);
    }
    else if (chStr >= 'a' && chStr <= 'f')
    {
    	//GPIO_DEBUG("chStr %c",chStr);
        return (chStr - 'a' + 10);
    }
    else
    {
    	//GPIO_DEBUG("chStr %c",chStr);
        return 0;
    }
}

unsigned char switch_mac_char_2_hex(char *src_char_mac,unsigned char *dst_mac)
{
    unsigned char achSrc[18];
    int  nIdx = 0;
    int  nTotal = 0;

 	memset(achSrc,0,18);
	memcpy(achSrc,src_char_mac,17);

	unsigned char *pchStr = strtok(achSrc, ":");
    while (NULL != pchStr) {
        dst_mac[nTotal] = ((switch_char_2_hex(*pchStr) << 4) & 0xf0) | (switch_char_2_hex(*(pchStr+1)) & 0x0f);
        pchStr = strtok(NULL, ":");
		nTotal++;
    }
    return 0;
}

/*
����:
    src      #dest:G1MQ4XG001555#type:set#ls&#
    dest
����:
    dest     dest:G1MQ4XG001555
    ָ���ܵ���һ��#
*/
char * rg_wds_cmp_str(char *src,char *dest)
{
    int i = 1;

    if (strlen(src) < 2) {
        return NULL;
    }

    while (src[i] != '#' || src[i] == 0) {
        dest[i - 1] = src[i];
        i++;
    }
    return src + i;
}


void rg_wds_sw_status_status(char *name,char port,char *link,char *speed,char *duplex) {
    char buf[100];
    char *p;
    char i = 0;
	FILE *fp;

    memset(buf,0,sizeof(buf));
    sprintf(buf,"swconfig dev %s port %d show | grep link",name,port);
	if((fp = popen(buf, "r")) == NULL) {
		goto end;
	}

	memset(buf,0,sizeof(buf));
	fread(buf,sizeof(char),sizeof(buf) - 1,fp);
    pclose(fp);

    p = strstr(buf,"up");

    if (p) {
        strcpy(link,"up");
    } else {
        goto end;
    }

    p = strstr(buf,"full-duplex");
    if (p) {
        strcpy(duplex,"full");
    } else {
        strcpy(duplex,"half");
    }

    p = strstr(buf,"10");

    while (1) {
        if (*(p + i) == ' ') {
            break;
        }

        speed[i] = *(p + i);
        i++;
        if (i>15) {
            break;
        }
    }

    return;
end:
    strcpy(link,"down");
    strcpy(speed,"off");
    strcpy(duplex,"off");
}

char rg_wds_get_dev_flow(unsigned long *rx_rate,unsigned long *tx_rate) {
    FILE * pFile;
    char mystring[200];
    char *p;
    unsigned long rx_now = 0;
    unsigned long tx_now = 0;
    static unsigned long rx_last = 0;
    static unsigned long tx_last = 0;
    static unsigned long time_last = 0;
	static unsigned long rx_rate_last = 0;
    static unsigned long tx_rate_last = 0;
	
    char buf[50];
    struct sysinfo info;

    //��ȡ��ǰʱ��
	sysinfo(&info);

    pFile = fopen("/proc/net/dev","r");
    if (pFile == NULL) {
        perror("Error opening file");
        return ;
    }

    memset(mystring,0,sizeof(mystring));
 	while (fgets(mystring,sizeof(mystring) - 1,pFile) != NULL ) {
        p = strstr(mystring,rg_ath_info_t.ath_wds_name);
        if (p) {
            sscanf(mystring,"%s %u %s %s %s %s %s %s %s %u %s %s %s %s %s %s %s",buf,&rx_now,buf,buf,buf,buf,buf,buf,buf,&tx_now,buf,buf,buf,buf,buf,buf,buf);
            break;
        }
        memset(mystring,0,sizeof(mystring));
 	}

    fclose (pFile);

    //��һ��
    if (time_last == 0 || rx_now == 0 || tx_now == 0) {
        *rx_rate = 0;
        *tx_rate = 0;
        rx_last = rx_now;
        tx_last = tx_now;
        time_last = info.uptime;
    } else {

		//The sending time interval is too short, using the last valid value
		if (info.uptime - time_last == 0) {
			*rx_rate = rx_rate_last;
			*tx_rate = tx_rate_last;
			GPIO_DEBUG("using the last valid value, rx_rate=%d, tx_rate=%d", *rx_rate, *tx_rate);
			return 0;
        }

		if ((rx_now - rx_last) > 0) {
            *rx_rate = (rx_now - rx_last)/(info.uptime - time_last);
            //GPIO_DEBUG("rx_now %d rx_last %d rx_rate %d time %d rate %d",rx_now,rx_last,*rx_rate,info.uptime - time_last,tx_now - tx_last);
        } else {
            *rx_rate = 0;
        }

        if ((tx_now - tx_last) > 0) {
            *tx_rate = (tx_now - tx_last)/(info.uptime - time_last);
            //GPIO_DEBUG("tx_now %d tx_last %d tx_rate %d time %d rate %d",tx_now,tx_last,*tx_rate,info.uptime - time_last,tx_now - tx_last);
        } else {
            *tx_rate = 0;
        }
        rx_last = rx_now;
        tx_last = tx_now;
        time_last = info.uptime;
    }
	
	//Effective rate saved
	rx_rate_last = *rx_rate;
	tx_rate_last = *tx_rate;
	GPIO_DEBUG("Effective rate saved rx_rate_last=%d, tx_rate_last=%d, time_last =%d, rx_now =%d, tx_now =%d", rx_rate_last, tx_rate_last, time_last, rx_now, tx_now);
    return 0;
}

/*
 * CPE��У�鱣������ģ����Ž��鷢�͵�ֱ�ӹ��˲�����
 */
int rg_cpe_check_setssid_condition(char *pkt)
{
    struct mac_ip_udp_wds_packet *L2_L3_L4_head = (struct mac_ip_udp_wds_packet *)pkt;
    struct wds_date_head *wds_pkt_head = (struct wds_date_head *)((u_char *)pkt + 44);

    /* cpe��û�й�����ap��Ҳ���ձ���� */
    if (rg_pair_info_heap_t == NULL) {
        GPIO_DEBUG("#SMB-UDP# CPE no found peer device!");
        return -1;
    }

    /* ����Ž�����,��ssid�Ѿ�����Ϊ��Ĭ�������Ҳ�������޸�ssid���� */
    if (rg_gpio_info_t.gpio_lock_value == LOCK &&
        strcmp(rg_ath_info_t.ssid, DEF_SSID) != 0) {
//        GPIO_DEBUG("#SMB-UDP# LOCK && UNdefault ssid, drop flag[%d] pkt!", wds_pkt_head->sync_flag);
        return -1;
    }

    return 0;
}

int rg_wds_check_udp_checksum(char *pkt)
{
    int checksumVal;
    int fir_udp_cs;
    int sec_udp_cs;
    int udp_len, udp_checksum;
	
    unsigned char pseudo_head[1500] = {
        0,  0,  0,  0,      //src_ip: 10.221.20.11
        0,  0,  0,  0,      //dst_ip: 10.221.20.10
        0x00,   17, 0x00, 0x00,    // 0,17,#--16λUDP����--20���ֽ�
    };
    struct wds_date_head *wds_pkt_head = (struct wds_date_head *)((u_char *)pkt + 44);

    /* αͷ���е�udp���ȣ�����ʵudp������ͬһ��ֵ�� */
    udp_len = *((unsigned short *)(pkt + WDS_ETH_HEAD_LEN + WDS_IP_HEAD_LEN + 4));
	
    /*UDP�ĳ��ȺϷ��Լ��*/
    *((unsigned short *)&pseudo_head[10]) =udp_len;
	udp_len = ntohs(udp_len);
	//GPIO_DEBUG("udp_len::::%d",udp_len);
    if (udp_len + WDS_PSEUDO_HEAD_LEN > sizeof(pseudo_head)) {
        GPIO_DEBUG("#SMB-UDP# PKT's len is too long!!!");
        return -1;
    }
    /*--����udpУ���ʱ��Ҫ����αͷ��--*/
    memcpy(pseudo_head + WDS_PSEUDO_HEAD_LEN, pkt + WDS_ETH_HEAD_LEN + WDS_IP_HEAD_LEN, udp_len);

    /* --��UDP���ݽ���У��-- */
    checksumVal = checksum((unsigned short *)pseudo_head, (udp_len + WDS_PSEUDO_HEAD_LEN) / 2);
	//GPIO_DEBUG("checksumVal:%d", checksumVal);

    return checksumVal;
}

static bool rg_wds_ap_udp_smac_check(u_int8_t *smac)
{
    bool flag = false;
    struct pair_dev_ath_info *p = rg_pair_info_heap_t;

    while (p) {
        if (memcmp(smac, p->mac, 6) == 0) {
            flag = true;
            break;
        }
        p = p->next;
    }

    return flag;
}

static bool rg_wds_cpe_udp_smac_check(u_int8_t *smac)
{	
	//����û�л�ȡ���Զ�mac��ַ��ʱ�򲻽���smac���
	if(!rg_pair_info_heap_t){
		GPIO_WARNING("rg_pair_info_heap_t is NULL,so  smac check!!!");
		return false;
	}
    return (memcmp(smac, rg_pair_info_heap_t->mac, 6) == 0 ? true : false);
}


static bool rg_wds_udp_smac_check(char *pkt)
{
    struct mac_ip_udp_wds_packet *L2_L3_L4_head = (struct mac_ip_udp_wds_packet *)pkt;
	
    if (rg_ath_info_t.role == MODE_CPE) {
        return rg_wds_cpe_udp_smac_check(L2_L3_L4_head->eth_header_date.ether_shost);
    } else if (rg_ath_info_t.role == MODE_AP) {
        return rg_wds_ap_udp_smac_check(L2_L3_L4_head->eth_header_date.ether_shost);
    }
}

/*
 * ���ն�У�����б���ģ��Ƿ�����ֱ�ӹ���
 */
int rg_wds_check_all_packet_validity(char *pkt)
{
    struct mac_ip_udp_wds_packet *L2_L3_L4_head;
    struct wds_date_head *wds_pkt_head;

    if (!pkt) {
        GPIO_DEBUG("#SMB-UDP# PKT NULL!");
        return -1;
    }

    L2_L3_L4_head = (struct mac_ip_udp_wds_packet *)pkt;
    wds_pkt_head = (struct wds_date_head *)((u_char *)pkt + 44);

    if (rg_wds_check_udp_checksum(pkt) != 0) {
        GPIO_DEBUG("#SMB-UDP# UDP's CHECKSUM BAD BAD BAD BAD!!!![%d]", wds_pkt_head->sync_flag);
        return -1;
    }

    /*
     * У�����ͷ��
     * 1������DMAC�ǵ�ǰ�豸��mac��ַ
     * 2������SMAC�ǶԶ�mac��ַ
     */
    if (memcmp(L2_L3_L4_head->eth_header_date.ether_dhost, rg_ath_info_t.root_mac_hex, 6) != 0) {
        GPIO_ERROR("#SMB-UDP# L2 DMAC not match![%s]",
            ether_sprintf(L2_L3_L4_head->eth_header_date.ether_dhost));
        GPIO_ERROR("dmac %s", ether_sprintf(rg_ath_info_t.root_mac_hex));
        return -1;
    }
    if (rg_wds_udp_smac_check(pkt) == false) {
        GPIO_DEBUG("#SMB-UDP# L2 SMAC not match![%s]", ether_sprintf(L2_L3_L4_head->eth_header_date.ether_shost));
        return -1;
    }
    /*
     * У������ͷ��
     * 1������DIP�Ƿ�ȫ��
     * 2������SIP�Ƿ�ȫ��
     */
//    if (*(data + 26) != 0 || *(data + 27) != 0 || *(data + 28) != 0 || *(data + 29) != 0) {
//        GPIO_DEBUG("#SMB-UDP# L3 DIP not match!");
//        return -1;
//    }
//    if (*(data + 30) != 0 || *(data + 31) != 0 || *(data + 32) != 0 || *(data + 33) != 0) {
//        GPIO_DEBUG("#SMB-UDP# L3 SIP not match!");
//        return -1;
//    }

    /*
     * У��payload�ı����־��
     * 1��wds�����ͷ��name�ֶΣ����Ͷ˾��̶�Ϊ��abcd��
     * 2��wds�����ͷ��unuse2�����Ͷ˾��̶�Ϊ0xaa
     */
    if (memcmp(wds_pkt_head->name, "abcd", strlen("abcd")) != 0) {
        GPIO_DEBUG("#SMB-UDP# UDP-payload name isn't our pkt![%d]", wds_pkt_head->sync_flag);
        return -1;
    }
    if (wds_pkt_head->unuse2 != 0xaa) {
        GPIO_DEBUG("#SMB-UDP# UDP-payload unuse2 isn't our pkt!");
        return -1;
    }

    return 0;
}

void rg_wds_uci_get_param(char *uci_param, char *buff, int len)
{
    struct uci_context *c;
    struct uci_ptr p;
    char *a;

    if (!uci_param || !buff) {
        GPIO_DEBUG("uci_param or buff is NULL!");
        return;
    }

    a = strdup(uci_param);
    c = uci_alloc_context();
    if (c == NULL || a == NULL) {
        GPIO_DEBUG("pointer is not valid.");
        goto err;
    }

    if (UCI_OK != uci_lookup_ptr(c, &p, a, true)) {
        GPIO_DEBUG("uci no found!");
        goto err;
    }

    if (p.o != NULL) {
       strncpy(buff, p.o->v.string, len);
    } else {
       GPIO_DEBUG("param %s not found", uci_param);
    }

err:
    if (c) {
       uci_free_context(c);
    }
    if (a) {
       free(a);
    }
    return;
}

bool rg_wds_dfs_test_flag(void)
{
    char buf[32];
    char dfs_path[] = "wds.main.dfs_test";

    memset(buf, 0, sizeof(buf));
    (void)rg_wds_uci_get_param(dfs_path, buf, sizeof(buf));
    if (atoi(buf) == 1) {
        return true;
    }
    return false;
}

bool rg_wds_func_test_flag(void)
{
    bool test_flag;

    test_flag = false;
    if (rg_wds_dfs_test_flag() == true) {
        test_flag = true;
    }

    return test_flag;
}

