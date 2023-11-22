#include <stdarg.h>
#include "rg_tipc.h"

#define RG_SMB_CMD_BUFSZ        512
#define RG_SMB_CMD_RETSZ        (512*1024)

int debug = 1;
char *rg_tipc_get_sn_from_msg(char *cmd_msg, int len){
    char up_sn[MAX_SN_NUM][SN_LENGTH];
    int i;
    char *sn_msg;
	
    if (!cmd_msg) {
        TIPC_DEBUG("cmd_msg is NULL");
        return NULL;
    }
	
	memset(up_sn, 0, sizeof(up_sn));
    memset(cmd_msg, 0, len);
    if (strlen(msg) <= 0) {
        return NULL;
    } else if (strlen(msg) == strlen(UPGRADE_REQ_CMD)) {
        /* if msg only  include "upgarde_req" */
        g_all_net_upgrade = 1;
        TIPC_DEBUG("Doind allnet upgrade");
        memcpy(cmd_msg, msg, len);
        TIPC_DEBUG("recv cmd_msg: %s", cmd_msg);
    } else {
        /* if msg includes sn and upgrade_req */
        g_all_net_upgrade = 0;
        TIPC_DEBUG("Doind Customized upgrade");
        sn_msg = strtok(msg, "#");

        /* save "upgrade_req" to cmd_msg */
        if (sn_msg) {
            memcpy(cmd_msg, sn_msg, len);
            TIPC_DEBUG("recv cmd_msg: %s", cmd_msg);
        }
        /* get sn and save to up_sn */
        i = 0;
        while (sn_msg != NULL) {
            sn_msg = strtok(NULL, "#");
            if (sn_msg) {
                memcpy(up_sn[i], sn_msg, sizeof(up_sn[i]));
                TIPC_DEBUG("recv upgrade_sn[%d]: %s", i, up_sn[i]);
            }
            i++;
        }
    }
    return up_sn;
}
int rg_mist_mac_2_nodeadd(unsigned char *mac_src){
    unsigned int mac[6];
    unsigned int tmp;
    char buf[30];

    memset(mac,0,sizeof(mac));
    if (sscanf(mac_src, "%2x:%2x:%2x:%2x:%2x:%2x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
        perror("please input right like :rg_tipc_mac_to_nodeadd aa:bb:cc:dd:ee:ffi \n");
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

    tmp = (mac[0] ^ mac[1] ^ mac[2]) & 0xff;
    tmp = (tmp & 0x0f) ^ (tmp >> 4);

    memset(buf,0,sizeof(buf));
    sprintf(buf,"%x%02x%02x%02x",tmp,mac[3],mac[4],mac[5]);

    tmp = 0;
    sscanf(buf,"%x",&tmp);
    return tmp;
}

int rg_exe_shell(char *buffer,int len){
    FILE *read_fp;
    int chars_read;

    /* popen函数访问"ps ax"命令给出的信恿	 * 第一个参敿ps ax"是要运行的程序名和相应的参数
     * 第二个参数open_mode="r"说明被调用程序的输出可以被调用程序使甿	 * 返回值为FILE*文件流指针read_fp,利用read_fp可以读取"ps ax"的输出信恿     * */
    read_fp = popen(buffer,"r");

    memset(buffer,0,len);
    strcpy(buffer,"sucess\n");
    buffer = buffer + strlen("sucess\n");

    if (read_fp != NULL) {
        /* fread函数从文件流指针read_fp指向的文件流中读取数捿		 * 最多读取BUFSIZ个元紿每个元素sizeof(char)个字芿		 * buffer用于接收数据的内存地址
         * 如果成功则返回实际读取的元素的个敿*/
        chars_read = fread(buffer,sizeof(char),len - strlen("sucess\n"),read_fp);
        printf("buffer %s\n",buffer);
        /* pclose关闭与popen关联的文件流(read_fp指向的文件流) */
        pclose(read_fp);
        return SUCESS;
    }
    pclose(read_fp);
    return FAIL;
}

char rg_misc_read_file(char *name,char *buf,char len) {
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

char  rg_misc_popen(char *cmd,char *buf,char len) {
	FILE *p;
	int i;
	if((p = popen(cmd, "r")) == NULL) {
		printf("%s %d fail/n",__func__,__LINE__);
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
    system(TIPC_REMOVE_TAR_FILE);
	return SUCESS;
}

char  rg_redis_popen(char *cmd,char *buf,char len) {
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

/* 等待消息函数 */
int wait_for_msg(int sd)
{
    struct pollfd pfd;
    int pollres;
    int res;

    pfd.events = ~POLLOUT; /* 等待消息事件 */
    pfd.fd = sd;           /* 等待的socket句柄 */
    pollres = poll(&pfd, 1, MAX_DELAY); /* 等待的poll函数，等待时间为MAX_DELAY */
    if (pollres < 0)
        res = -1;
    else if (pollres == 0)
        res = -2;
    else
        res = (pfd.revents & POLLIN) ? 0 : pfd.revents;
    return (res);
}

int wait_for_server(__u32 name_type, __u32 name_instance, int wait)
{
	struct sockaddr_tipc topsrv;
	struct tipc_subscr subscr;
	struct tipc_event event;

	int sd = socket(AF_TIPC,SOCK_SEQPACKET,0);

	memset(&topsrv, 0, sizeof(topsrv));
	topsrv.family = AF_TIPC;
	topsrv.addrtype = TIPC_ADDR_NAME;
	topsrv.addr.name.name.type = TIPC_TOP_SRV;
	topsrv.addr.name.name.instance = TIPC_TOP_SRV;

	/* Connect to topology server */
	if (0 > connect(sd, (struct sockaddr *)&topsrv, sizeof(topsrv))) {
        goto error;
	}

	subscr.seq.type = htonl(name_type);
	subscr.seq.lower = htonl(name_instance);
	subscr.seq.upper = htonl(name_instance);
	subscr.timeout = htonl(wait);
	subscr.filter = htonl(TIPC_SUB_SERVICE);

	if (send(sd, &subscr, sizeof(subscr), 0) != sizeof(subscr)) {
        goto error;
	}

	/* Now wait for the subscription to fire */
	if (recv(sd, &event, sizeof(event), 0) != sizeof(event)) {
        goto error;
	}
	if (event.event != htonl(TIPC_PUBLISHED)) {
        goto error;
	}

	close(sd);
    return SUCESS;
error:
    close(sd);
    return FAIL;
}

void rg_sn_to_mac(char *sn,char *mac)
{
    struct sockaddr_in addr;
    int sockfd, len = 0;
    int addr_len = sizeof(struct sockaddr_in);
    char buffer[50];
    struct timeval timeout_send={4,0};
    /* 建立socket，注意必须是SOCK_DGRAM */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    /* 填写sockaddr_in*/
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    bzero(buffer, sizeof(buffer));

    memcpy(buffer,"sn_2_mac",strlen("sn_2_mac"));
    strcpy(buffer + strlen("sn_2_mac"),sn) ;
    //printf("buffer %s\n",buffer);
    setsockopt(sockfd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout_send,sizeof(struct timeval));
    sendto(sockfd,buffer,strlen(buffer),0,(struct sockaddr *)&addr,addr_len);

    /* 接收server端返回的字符丿/*/
    struct timeval timeout={0,100*1000};
    char num = 0;
    len = 0;
    setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));
    while(1){
        len = recvfrom(sockfd,mac,20,0,(struct sockaddr *)&addr,&addr_len);
        if (num++ > 6 || len > 0) {
            break;
        }
    }
    //printf("Receive from server: %s\n", buffer);

    return;
}

void rg_mac_to_softver(char *mac,char *softver)
{
    struct sockaddr_in addr;
    int sockfd, len = 0;
    int addr_len = sizeof(struct sockaddr_in);
    char buffer[50];
    struct timeval timeout_send={4,0};
    /* 建立socket，注意必须是SOCK_DGRAM */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    /* 填写sockaddr_in*/
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    bzero(buffer, sizeof(buffer));

    memcpy(buffer,"mac_2_softver",strlen("mac_2_softver"));
    strcpy(buffer + strlen("mac_2_softver"),mac) ;

    //printf("buffer %s\n",buffer);
    setsockopt(sockfd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout_send,sizeof(struct timeval));
    sendto(sockfd,buffer,strlen(buffer),0,(struct sockaddr *)&addr,addr_len);

    /* 接收server端返回的字符丿/*/
    struct timeval timeout={0,100*1000};
    char num = 0;
    len = 0;
    setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));
    while(1){
        len = recvfrom(sockfd,softver,64,0,(struct sockaddr *)&addr,&addr_len);
        if (num++ > 6 || len > 0) {
            break;
        }
    }
    //printf("Receive from server: %s\n", softver);

    return;
}


int sock_bind(int lisfd, int port)
{
	memset((char *)&myaddr, 0, sizeof(struct sockaddr_in));//ȥ£
	myaddr.sin_family = AF_INET;//IPV4
	myaddr.sin_port = htons(port);//׋ࠚ
	myaddr.sin_addr.s_addr = inet_addr("127.0.0.1");//Պѭlޓս̹ԐѾַ֘֘ʏ
	if (bind(lisfd, (struct sockaddr *)&myaddr, sizeof(struct sockaddr))==-1)
	{
		perror("sock_bind failed!\n");
	}
	return 0;
}

void *rg_tipc_malloc(size_t size)
{
    void *ptr;

    if (size <= 0) {
        TIPC_DEBUG("size too short!");
        return NULL;
    }

    ptr = malloc(size);
    if (!ptr) {
        TIPC_DEBUG("malloc mem err!");
        return NULL;
    }

    memset(ptr, 0, size);

    return ptr;
}

char *rg_tipc_strdup(char *ptr)
{
    char *temp;

    temp = strdup(ptr);

    return temp;
}

char *rg_tipc_execute_buf(const char *fmt, ...)
{
    char cmd[RG_SMB_CMD_BUFSZ], buf[RG_SMB_CMD_RETSZ];
    va_list args;
    FILE *fp;

    memset(cmd, 0, sizeof(cmd));
    va_start(args, fmt);
    (void) vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);

    memset (buf, 0, sizeof(buf));
    fp = popen(cmd, "r");
    if (fp == NULL) {
        return NULL;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (buf[strlen(buf) - 1] == '\n') {
            buf[strlen(buf) - 1] = '\0';
        }
        break;
    }
    pclose(fp);

    if (strlen(buf) == 0) {
        return NULL;
    }

    return rg_tipc_strdup(buf);
}

/*
 * rg_smb_strrpc: string replace
 */
unsigned char *rg_tipc_strrpc(unsigned char *str, int len, char *oldstr, char *newstr)
{
    unsigned char bstr[len];
    int i;

    if (!str) {
        TIPC_DEBUG("str is NULL!");
        return NULL;
    }

    if (len <= 0) {
        TIPC_DEBUG("len too short!");
        return NULL;
    }

    if (!oldstr) {
        TIPC_DEBUG("oldstr is NULL!");
        return NULL;
    }

    if (!newstr) {
        TIPC_DEBUG("newstr is NULL!");
        return NULL;
    }

    memset(bstr, 0, len);
    for (i = 0; i < strlen(str); i++) {
        if(!strncmp(str + i, oldstr, strlen(oldstr))){
            strcat(bstr, newstr);
            i += strlen(oldstr) - 1;
        }else{
            strncat(bstr, str + i, 1);
        }
    }
    strcpy(str, bstr);

    return str;
}

//int rg_create_tipc_handshake_file(unsigned char *sn, unsigned char *upgrade_cmd)
//{
//    char filename[48];
//    char hs_name[4];
//    unsigned char *tmp_mac;
//    int ret;
//    FILE *fp;

//    memset(hs_name, 0, sizeof(hs_name));
//    if (!strcmp(upgrade_cmd, UPGRADE_REQ_CMD)) {
//        strcpy(hs_name, "hs1");
//    } else if (!strcmp(upgrade_cmd, UPGRADE_HS2_CMD)) {
//        strcpy(hs_name, "hs2");
//    } else if (!strcmp(upgrade_cmd, UPGRADE_HS3_CMD)) {
//        strcpy(hs_name, "hs3");
//    } else if (!strcmp(upgrade_cmd, UPGRADE_HS4_CMD)) {
//        strcpy(hs_name, "hs4");
//    }

//    memset(filename, 0, sizeof(filename));
//    snprintf(filename, sizeof(filename) - 1, "/tmp/tipc_%s.txt", sn);

//    if (access(filename, 0) == 0) {
//        ret = remove(filename);
//        if (ret != 0) {
//            TIPC_DEBUG("remove err.");
//        }
//        TIPC_DEBUG("remove suc.");
//    }
//    fp = fopen(filename, "w");
//    if (fp == NULL) {
//        TIPC_DEBUG("create file fail!");
//        return -1;
//    }
//    fclose(fp);
//    TIPC_DEBUG("create file[%s] suc!", filename);

//    return 0;
//}

void rg_mac_2_big(char *native_mac, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (*native_mac >= 'a' && *native_mac <= 'z') {
            *native_mac = *native_mac - 32;
        }
        native_mac++;
    }
}

bool rg_version_sync_check(char *upgrd_ver, char *peer_ver)
{
    if (!upgrd_ver) {
        TIPC_DEBUG("native version is NULL!");
        return false;
    }

    if (!peer_ver) {
        TIPC_DEBUG("peer version is NULL!");
        return false;
    }

    return ((strcmp(peer_ver, upgrd_ver) != 0) && (atoi(upgrd_ver) >= atoi(peer_ver)));
}

unsigned char *rg_filter_ver_to_int(char *version)
{
    unsigned char *tmp_version;

    if (!version) {
        TIPC_DEBUG("native software-version is NULL");
        return NULL;
    }
    
    tmp_version = strrchr(version, '(');
    if (!tmp_version) {
        TIPC_DEBUG("int number filter err.");
        return NULL;
    }
    tmp_version = rg_tipc_strrpc(tmp_version + 1, strlen(tmp_version + 1), ")", "");
    if (!tmp_version) {
        TIPC_DEBUG("string repalce err!");
        return NULL;
    }
    return tmp_version;
}

int rg_filter_softversion_devtype(unsigned char *softversion,
                                             unsigned char *dev_type,
                                             unsigned char *version_name)
{
    unsigned char *tmp_version, *tmp_version_1, *softver;
    int len;

    if (!softversion) {
        TIPC_DEBUG("native software-version is NULL");
        return FAIL;
    }

    if (!dev_type) {
        TIPC_DEBUG("dev_type is NULL");
        return FAIL;
    }

    if (!version_name) {
        TIPC_DEBUG("version_name is NULL");
        return FAIL;
    }

    softver = softversion;
    /* 最后一次出现字笿_'的位罿 )B2P8_EST301_06133110.tar.gz */
    tmp_version = strrchr(softver, ')');
    if (!tmp_version) {
        return FAIL;
    }
    /* 第一次出现字笿E'的位罿 EST301_06133110.tar.gz */
    tmp_version = strchr(tmp_version, 'E');
    if (!tmp_version) {
        return FAIL;
    }
    /* 最后一次出现字笿_'的位罿 _06133110.tar.gz */
    tmp_version_1 = strrchr(tmp_version, '_');
    if (!tmp_version_1) {
        return FAIL;
    }
    strncpy(version_name, tmp_version_1 + 1, UPGRADE_VER_LEN);

    /* “EST301_06133110.tar.gz‿- “_06133110.tar.gz‿= “EST301‿*/
    len = tmp_version_1 - tmp_version;
    strncpy(dev_type, tmp_version, len);

    return SUCESS;
}

int rg_tipc_check_download_version(unsigned char *version_name)
{
    unsigned char rmt_type[16], rmt_ver_num[12], native_type[16], ntv_ver[48], type_from_pid[64];
    unsigned char *ntv_ver_num, *version;
    int ret;

    if (!version_name) {
        TIPC_DEBUG("version_name is NULL.");
        ret = FAIL;
        goto end;
    }

    memset(native_type, 0, sizeof(native_type));
    rg_misc_read_file("/proc/rg_sys/product_class", native_type, sizeof(native_type) - 1);
    memset(ntv_ver, 0, sizeof(ntv_ver));
    rg_misc_read_file("/proc/rg_sys/software_version", ntv_ver, sizeof(ntv_ver) - 1);
    ntv_ver_num = rg_filter_ver_to_int(ntv_ver);
    if (!ntv_ver_num) {
        TIPC_DEBUG("Convert version to int fail!");
        ret = FAIL;
        goto end;
    }

    version = rg_tipc_execute_buf(TIPC_RMT_TAR_SOFTVER, version_name);
    if (!version) {
        TIPC_DEBUG("Execute cmd[%s] error!", TIPC_RMT_TAR_SOFTVER);
        ret = FAIL;
        goto end;
    }

    memset(rmt_type, 0, sizeof(rmt_type));
    memset(rmt_ver_num, 0, sizeof(rmt_ver_num));
    ret = rg_filter_softversion_devtype(version, rmt_type, rmt_ver_num);
    if (ret == FAIL) {
        TIPC_DEBUG("Version unmatch!!!");
        ret = FAIL;
        goto end;
    }
	if (rg_misc_popen(TIPC_GET_SOFTVER_FROM_PID, type_from_pid, sizeof(type_from_pid)) == -1) {
		TIPC_DEBUG("TIPC_GET_SOFTVER_FROM_PID err!!!");
        ret = FAIL;
        goto end;	
	}
//    TIPC_DEBUG("version %s rmt_type %s rmt_ver_num %s", version, rmt_type, rmt_ver_num);
	
    if (strstr(type_from_pid, native_type) == NULL) {
        TIPC_DEBUG("dev type unmatch!!!");
        ret = FAIL;
        goto end;
    }

    if (rg_version_sync_check(rmt_ver_num, ntv_ver_num) == false) {
        TIPC_DEBUG("version unmatch!!!");
        ret = FAIL;
        goto end;
    }

    ret = SUCESS;
end:
    if (version) {
        free(version);
        version = NULL;
    }

    return ret;
}

int rg_tipc_client_download_targz(unsigned char *trans_sn,
                                             unsigned char *peer_sn,
                                             unsigned char *upgrade_cmd)
{
    unsigned char native_sn[20], mac[20];
    unsigned int instance;
    unsigned char buf[BUF_SIZE];
    struct sockaddr_tipc server_addr, client_addr;
    socklen_t length = sizeof(client_addr);
    int sd, ret;

    if (!trans_sn) {
        TIPC_DEBUG("trans_sn is NULL!");
        ret = FAIL;
        goto end;
    }

    if (!peer_sn) {
        TIPC_DEBUG("peer_sn is NULL!");
        ret = FAIL;
        goto end;
    }

    if (!upgrade_cmd) {
        TIPC_DEBUG("upgrade_cmd is NULL!");
        ret = FAIL;
        goto end;
    }

//    if (strcmp(upgrade_cmd, UPGRADE_REQ_CMD) != 0 &&
//        strcmp(upgrade_cmd, UPGRADE_HS2_CMD) != 0 &&
//        strcmp(upgrade_cmd, UPGRADE_HS3_CMD) != 0 &&
//        strcmp(upgrade_cmd, UPGRADE_HS4_CMD) != 0) {
//        TIPC_DEBUG("UPGRADE CMD ERR.");
//        ret = FAIL;
//        goto end;
//    }

    /* Get native serial number */
    memset(native_sn, 0, sizeof(native_sn));
    rg_misc_read_file("/proc/rg_sys/serial_num", native_sn, sizeof(native_sn) - 1);

    if (strlen(peer_sn) != 17 && !strchr(peer_sn, ':')) {
        memset(mac,0,sizeof(mac));
        char num = 0;
        while(1){
            rg_sn_to_mac(peer_sn, mac);
            if (num++ > 3 || strlen(mac) == 17) {
                break;
            }
        }
        if (strlen(mac) != 17) {
            printf("error\n");
            ret = FAIL;
            goto end;
        }
        instance = rg_mist_mac_2_nodeadd(mac);
    } else {
        instance = rg_mist_mac_2_nodeadd(peer_sn);
    }

    if (instance == 0) {
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    memset(buf,0,sizeof(buf));
    snprintf(buf, BUF_SIZE, "%s#%s#%s", upgrade_cmd, trans_sn, native_sn);
    strncpy(buf, upgrade_cmd, strlen(upgrade_cmd));
//    TIPC_DEBUG("buf:%s", buf);

    if (wait_for_server(SERVER_TYPE_DOWNLOAD, instance, 3000) == FAIL){
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    sd = socket(AF_TIPC, SOCK_STREAM, 0);
    if (sd < 0) {
        TIPC_DEBUG("socket create err.");
        ret = FAIL;
        goto end;
    }

    server_addr.family                  = AF_TIPC;
    server_addr.addrtype                = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type     = SERVER_TYPE_DOWNLOAD;
    server_addr.addr.name.name.instance = instance;
    server_addr.addr.name.domain        = 0;

    if (0 > connect(sd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        TIPC_DEBUG("connect error");
        ret = FAIL;
        goto end;
    }

//    if (0 > sendto(sd, buf, strlen(buf), 0, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
//        TIPC_DEBUG("sendto error");
//        ret = FAIL;
//        goto end;
//    }
    memset(buf, 0, sizeof(buf));
    if (0 >= recvmsg(sd, buf, 0)) {
        TIPC_DEBUG("unexpected message");
        ret = FAIL;
        goto end;
    }
    TIPC_DEBUG("#zhangyz# buf %s", buf);
    ret = SUCESS;
end:
    if (sd) {
        close(sd);
    }

    return ret;
}

int rg_tipc_get_upgrade_bin(unsigned char *sn, unsigned char *version_name)
{
    char cmd[512];
    char *dl_monitor_proc, *ver_name;
    int ret;

    if (!sn) {
        TIPC_DEBUG("sn is NULL.");
        ret = FAIL;
        goto end;
    }

    if (!version_name) {
        TIPC_DEBUG("version_name is NULL.");
        ret = FAIL;
        goto end;
    }
    /*
     * if tftp_monitor.sh is running, indicated upgrade action
     * is upgrading, no repeating to execute corresponding process.
     * tftp_monitor.sh: it's process ran by backgroud. it uses for
     * monitoring the process status of wds_upgrade.sh, if tftp-hpa
     * downloading upgrade bin over 5mins, this process will delete
     * incomplete upgrade bin and kill tftp-hpa's process.
     */
    dl_monitor_proc = rg_tipc_execute_buf(TIPC_DOWNLOAD_MONITOR);
    if (strcmp(dl_monitor_proc, "1") == 0) {
        TIPC_DEBUG("tipc_download_monitor is running.");
        ret = FAIL;
        goto end;
    }
    system(TIPC_DL_MONITOR_SH);
    sleep(1);
    /*
     * "tftp_monitor.sh" will check "wds_upgrade.sh"
     * process does exist before? must wait a little
     * time to execute command.
     */
    memset(cmd, 0, sizeof(cmd));

    snprintf(cmd, sizeof(cmd), "%s %s %s", "wds_upgrade.sh", sn, version_name);
    system(cmd);
    ver_name = rg_tipc_execute_buf(GET_TMP_SOFTVERSION);
    if (!ver_name) {
        TIPC_DEBUG("exec cmd[%s] fail!", GET_TMP_SOFTVERSION);
        ret = FAIL;
        goto end;
    }

    ret = rg_tipc_check_download_version(ver_name);
    if (ret == FAIL) {
        TIPC_DEBUG("[%s] download prepare fail", ver_name);
        ret = FAIL;
        goto end;
    }

end:
    if (dl_monitor_proc) {
        free(dl_monitor_proc);
        dl_monitor_proc = NULL;
    }
    if (ver_name) {
        free(ver_name);
        ver_name = NULL;
    }

    return ret;
}

int rg_tipc_check_upgrd_status(void)
{
    char *dl_proc = NULL;

    /*
     * 1. "rg_tipc_client_upgrade" no running and "firmware.img" exist,
     * it needs to delete file and continue to upgrade.
     * 2. "rg_tipc_client_upgrade" no running and "firmware.img" no exist,
     * continue to upgrade.
     * 3. "rg_tipc_client_upgrade" is running, stop it.
     */
    dl_proc = rg_tipc_execute_buf(TIPC_CLI_DOWNLOAD_PROC);
    if (!dl_proc) {
        if (access(TIPC_TMP_SOFTVERSION, F_OK) == 0) {
            system(RM_TMP_VERSION);
        }
        return SUCESS;
    } else {
        free(dl_proc);
        dl_proc == NULL;
        return FAIL;
    }
}

