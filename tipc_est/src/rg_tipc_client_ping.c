#include "rg_tipc.h"
#include<sys/resource.h>

int main(int argc,char *argv[])
{
    int sd;
    struct sockaddr_tipc server_addr;
    unsigned int instance = 0;
    unsigned char buf[BUF_SIZE_PING];
    char *tmp;
    int flag;
    int timeout_d = 0;
    int num = 0;
    struct timeval timeout={1,0};
    unsigned char mac[20];
    struct timeval start,end;
    long start_m,end_m;
    int i;
    long sum = 0;
    int j = 0;
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif
    if (argc != 4) {
        perror("fuck:rg_tipc_client_shell aa:bb:cc:dd:ee:ff delaytime count\n");
        exit(1);
    }

    instance = rg_mist_mac_2_nodeadd(argv[1]);
    timeout_d = atoi(argv[2]);
    if (timeout_d == 0) {
        timeout_d = 1;
    }

    num = atoi(argv[3]);
    if (num == 0) {
        num = 1;
    }

    if (wait_for_server(SERVER_TYPE_PING,instance,timeout_d * 1000) == FAIL){
        goto end;
    }

    timeout.tv_sec = timeout_d;

    sd = socket(AF_TIPC,SOCK_RDM,0);
    if (sd < 0) {
        printf("socket error\n");
        return;
    }

    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type = SERVER_TYPE_PING;
    server_addr.addr.name.name.instance = instance;
    server_addr.addr.name.domain = 0;
    
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
    setsockopt(sd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));
    
    for(i = 0;i < num;i++){
        gettimeofday(&start,NULL);
        if (0 > sendto(sd,buf,sizeof(buf) - 1,0,(struct sockaddr*)&server_addr,sizeof(server_addr))) {
            goto loop;
        }
        start_m = ((long)start.tv_sec)*1000+(long)start.tv_usec/1000;
        if (0 >= recv(sd,buf,sizeof(buf) - 1,0)) {
            goto loop;
        }
        gettimeofday(&end,NULL);
        end_m = ((long)end.tv_sec)*1000+(long)end.tv_usec/1000;
        sum = sum + (end_m - start_m);
        j++;
        printf("i %d delay %dms\n",i,end_m - start_m);
        sleep(1);
        continue;
loop:
        sleep(1);
        printf("timeout %d \n",i);
    }
    if (j == 0) {
        goto end;
    }
    printf("count %d average:%dms\n",j,sum/j);

    close(sd);
    return;
end:
    if (sd) {
        close(sd);
    }
    printf("average:timeout\n");
}
