#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/tipc.h>
#include<sys/resource.h>
int main(int argc, char *argv[]){
    unsigned int mac[6];
    unsigned int tmp;
    char buf[30];
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif
    if (argc != 2) {
        printf("please input right like :rg_tipc_mac_to_nodeadd aa:bb:cc:dd:ee:ffi \n");
        exit(0);
    }

    memset(mac,0,sizeof(mac));
    if (sscanf(argv[1], "%2x:%2x:%2x:%2x:%2x:%2x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
        printf("please input right like :rg_tipc_mac_to_nodeadd aa:bb:cc:dd:ee:ffi \n");
        exit(0);
    }

    /* ********************************************************************
     * bug 1023648,处理xx:xx:xx:00:0x:xx和xx:xx:xx:xx:x0:00这类mac设置tipc的node地址设置不下去的问题 
     * 规则参照设备mac地址规则 参见http://conf.ruijie.work/pages/viewpage.action?pageId=49187486
     */
    if((mac[3] == 0) && ((mac[4] & 0xf0) == 0)) {
        mac[3] = mac[3] + 16;
    }

    if((mac[5] == 0) && ((mac[4] & 0x0f) == 0)) {
        mac[5] = mac[5] + 2;
    }
    /************************************************************************/

    //printf("%2x:%2x:%2x:%2x:%2x:%2x \n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    tmp = (mac[0] ^ mac[1] ^ mac[2]) & 0xff;
    tmp = (tmp & 0x0f) ^ (tmp >> 4);
    //printf("success:%d\n",tmp);

    memset(buf,0,sizeof(buf));
    sprintf(buf,"%x%02x%02x%02x",tmp,mac[3],mac[4],mac[5]);
    //printf("buf %s\n",buf);

    tmp = 0;
    sscanf(buf,"%x",&tmp);
    printf("reslut:%d\n",tmp);
}
