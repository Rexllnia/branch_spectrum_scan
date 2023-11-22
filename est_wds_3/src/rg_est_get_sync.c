/**
 *  Copyright (C)2017 Ruijie Network.  All rights reserved.
 */
/**
 * sys_led.c
 * Original Author:  zhengjunqiang@ruijie.com.cn, 2017-12-11
 *
 */
#include "rg_wds.h"

int rg_wds_send_message_udp(char * sendline)
{
    int sock;
    struct sockaddr_in servaddr;
    char recvbuf[20] = {0};
    struct timeval tv;
    int port = 5000;

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    memset(&servaddr, 0, sizeof(servaddr));
    memset(recvbuf, 0, sizeof(recvbuf));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        exit(1);
    }

    sendto(sock, sendline, strlen(sendline), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

    //设置超时为1S
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        exit(1);
    }

    close(sock);
}

int main(int argc, char *argv[])
{
    int n = 0;
    char buf[3000];
    int fd;
    char str[10];
    struct sysinfo info;

	//获取当前时间
	sysinfo(&info);

    memset(buf,0,sizeof(buf));
    strcpy(buf,"get ");
    n = n + strlen("get ");

    fd = getpid();
    memset(str,0,sizeof(str));
    sprintf(str,"%d%d ",fd,info.uptime);

    strcpy(buf + n,str);
    n = n + strlen(str);

    gets(buf + n);
    rg_wds_send_message_udp(buf);
    printf("%s\n",buf);

    while(1) {
        sleep(1);

    }
}
