/**
 * Copyright (C)2017 Ruijie Network.  All rights reserved.
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

    //ÉèÖÃ³¬Ê±Îª1S
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        exit(1);
    }

    close(sock);
}

int main(int argc, char *argv[])
{
/*
    memset(buf,0,sizeof(buf));

    if (argc < 3) {
        exit(0);
    }
    
    memcpy(buf + len,argv[1],strlen(argv[1]));
    buf[len + strlen(argv[1])] = ' ';
    len += strlen(argv[1]) + 1;

    
    for(i = 2;i < argc;i++) {
        memcpy(buf + len,argv[i],strlen(argv[i]));
        if (i != (argc -1)) {
            buf[len + strlen(argv[i])] = ' ';
        }
        len += strlen(argv[i]) + 1;
    }

    printf("%s %d %s\n",__func__,__LINE__,buf);
*/
    int n;
    char buf[3000];

    memset(buf,0,sizeof(buf));
    gets(buf);
    printf("str %s\n",buf);
    
    rg_wds_send_message_udp(buf);
}
