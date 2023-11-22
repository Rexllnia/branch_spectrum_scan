#include "rg_tipc.h"
#include<sys/resource.h>
void main(int argc,char *argv[])
{
    int sock;
    struct sockaddr_in servaddr;
    char buf[SIZE];
    struct timeval tv;
    struct timeval timeout={4,0};
    int port = 5005;
    int num;
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif
    if (argc < 2) {
        perror("Usage: rg_tipc_client_upgrade [upgrade_req] ([sn])\n");
        exit(1);
    }

    memset(buf, 0, sizeof(buf));
    if (argc == 2) {
        strncpy(buf, argv[1], strlen(argv[1]));
    } else {
        num = 1;
        while (num < argc) {
            strcat(buf, argv[num]);
            strcat(buf, "#");
            num++;
        }
    }

    if (strcmp(argv[1], UPGRADE_REQ_CMD) != 0) {
        perror("Usage: rg_tipc_client_upgrade [upgrade_req] [sn]\n");
        exit(1);
    }
    
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        TIPC_DEBUG("socket create err!");
        exit(1);
    }

    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
    if (0 >= sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
        TIPC_DEBUG("sendto fail!");
        exit(1);
    }
    /* set overtime 1s*/
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        TIPC_DEBUG("socket timeout!");
        exit(1);
    }

    close(sock);

    return;
}

