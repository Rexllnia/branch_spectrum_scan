#include "rg_tipc.h"
#include<sys/resource.h>
int main()
{
	struct sockaddr_tipc server_addr;
	struct sockaddr_tipc client_addr;
	socklen_t alen = sizeof(client_addr);
	int sd;
    char *buf_relay = "test";
	char buf[BUF_SIZE_PING];
    unsigned int instant = 0;
    unsigned char mac[20];
    struct timeval timeout={4,0};
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif
begin:
    memset(mac,0,sizeof(mac));
    rg_misc_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);

    instant = rg_mist_mac_2_nodeadd(mac);
    if (instant == 0) {
        printf("%s %d error exit instant %d\n",__func__,__LINE__,instant);
        sleep(5);
        goto begin;
    }

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAMESEQ;
	server_addr.addr.nameseq.type = SERVER_TYPE_PING;
	server_addr.addr.nameseq.lower = instant;
	server_addr.addr.nameseq.upper = instant;
	server_addr.scope = TIPC_ZONE_SCOPE;

	sd = socket(AF_TIPC,SOCK_RDM,0);
    if (sd < 0) {
        sleep(10);
        close(sd);
        goto begin;
    }

	if (0 != bind(sd,(struct sockaddr *)&server_addr,sizeof(server_addr))){
		printf("Server: failed to bind port name\n");
        sleep(10);
        close(sd);
        goto begin;
	}
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
    while(1){
        if (0 >= recvfrom(sd,buf,sizeof(buf) - 1,0,(struct sockaddr *)&client_addr,&alen)) {
            perror("Server: unexpected message");
            sleep(10);
            close(sd);
            goto begin;
        }

        if (0 > sendto(sd,buf,sizeof(buf) - 1,0,(struct sockaddr *)&client_addr,sizeof(client_addr))){
            perror("Server: failed to send");
            sleep(10);
            close(sd);
            goto begin;
        }
    }
}
