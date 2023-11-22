/*server.c_非阻塞式*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#include "rg_wds.h"

#define SIZE 3000
int lisfd;
//struct sockaddr_in cliaddr;
struct sockaddr_in myaddr;

char msg[SIZE];

int sock_bind(int lisfd, int port)
{
	memset((char *)&myaddr, 0, sizeof(struct sockaddr_in));//清零
	myaddr.sin_family = AF_INET;//IPV4
	myaddr.sin_port = htons(5000);//端口
	myaddr.sin_addr.s_addr = inet_addr("127.0.0.1");//允许连接到所有本地地址上
	if (bind(lisfd, (struct sockaddr *)&myaddr, sizeof(struct sockaddr))==-1)
	{
		perror("sock_bind failed!\n");
		return FAIL;
	}
	return SUCESS;
}

int rg_wds_udp_recv_init() {
	int i;
	int flag;
	socklen_t len;

	bzero(msg, SIZE);
	lisfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sock_bind(lisfd, 5000) == FAIL){
		GPIO_ERROR("sock_bind fail!");
		close(lisfd);
		lisfd = 0;
		return FAIL;
	}
	GPIO_WARNING("sock_bind success");
    /*
	flag = fcntl(lisfd,F_GETFL,0);
	if (flag < 0)
	{
		perror("fcntl failed.\n");
	}
	flag |= O_NONBLOCK;
	if (fcntl(lisfd, F_SETFL, flag) < 0)
	{
		perror("fcntl failed.\n");
	}
    */
}

int rg_wds_message_process(struct sockaddr_in peeraddr)
{
    char sn[50];
	char mac[50];
    int i = 0;
    int len = 0;
    char buf[50];

    if (strlen(msg) <= 0) {
        return 0;
    }

    if (memcmp(msg,"wds_all_info",strlen("wds_all_info")) == 0) {
        rg_wds_write_info_all_list();
    } else if (strncmp(msg,CMD_SN_2_MAC,strlen(CMD_SN_2_MAC)) == 0) {
        memset(sn,0,sizeof(sn));
        strcpy(sn,msg + strlen(CMD_SN_2_MAC));
        //如果是本机SN什么都不处理
        if (strcmp(sn,rg_dev_info_t.sn) == 0 || strcmp(sn,"all") == 0) {
            return 0;
        }
        memset(buf,0,sizeof(buf));
        rg_wds_sn_2_mac(sn,buf);
        buf[17] = 0;
        sendto(lisfd,buf,strlen(buf),0,(struct sockaddr *)&peeraddr,sizeof(struct sockaddr_in));
		GPIO_DEBUG("send mac to tipc:%s",buf);
    } else if (strncmp(msg,CMD_MAC_2_SOFTVER,strlen(CMD_MAC_2_SOFTVER)) == 0) {
        memset(mac,0,sizeof(mac));
        strcpy(mac,msg + strlen(CMD_MAC_2_SOFTVER));
        //如果是本机mac什么都不处理
        if (strcmp(mac,rg_dev_info_t.sys_mac) == 0) {
            return 0;
        }
        memset(buf,0,sizeof(buf));
        rg_wds_mac_2_softver(mac,buf);
        sendto(lisfd,buf,strlen(buf),0,(struct sockaddr *)&peeraddr,sizeof(struct sockaddr_in));
    }
}

int rg_wds_udp_process()
{
    int nbytes;
    struct sockaddr_in peeraddr;
    socklen_t len;
begin:
    if (lisfd <= 0) {
        GPIO_DEBUG("lisfd %d",lisfd);
        rg_wds_udp_recv_init();
        sleep(1);
        goto begin;
    }
    while(1){
        memset(msg,0,sizeof(msg));
        nbytes = recvfrom(lisfd,msg,SIZE,0,(struct sockaddr *)&peeraddr, &len);

        if (nbytes > 0) {
            rg_wds_message_process(peeraddr);
        }
    }
}
