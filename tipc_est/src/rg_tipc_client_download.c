#include "rg_tipc.h"
#include<sys/resource.h>

static int rg_tipc_client_md5_check(char *file_name, char *buf, int recv_len)
{
    unsigned char *send_len, *send_md5, *native_md5;
    int ret, slen = 0, smd5 = 0;
    unsigned char md5_cmd[128];

    if (!buf) {
        TIPC_DEBUG("buf is NULL!");
        return FAIL;
    }

    if (!file_name) {
        TIPC_DEBUG("file_name is NULL!");
        return FAIL;
    }

    send_len = strtok(buf + strlen(TIPC_UPGRD_FINI_STR), "#");
    if (send_len) {
        slen = atoi(send_len);
        send_md5 = strtok(NULL, "#");
//        TIPC_DEBUG("send_len %s slen %d send_md5 %s", send_len, slen, send_md5);
    }

    if (slen != recv_len) {
        TIPC_DEBUG("recvlen unmatch!!!");
        ret = FAIL;
        goto end;
    }

    /*
     * send the md5sum and total length
     */
    memset(md5_cmd, 0, sizeof(md5_cmd));
    snprintf(md5_cmd, sizeof(md5_cmd) - 1, TIPC_MD5_CMD, file_name);
    native_md5 = rg_tipc_execute_buf(md5_cmd);
    if (!native_md5) {
        TIPC_DEBUG("Execute cmd[%s] error!", md5_cmd);
        ret = FAIL;
        goto end;
    }

    if (memcmp(native_md5, send_md5, strlen(send_md5)) != 0) {
        TIPC_DEBUG("md5 unmatch!!!");
        ret = FAIL;
        goto end;
    }

    ret = SUCESS;
end:
    if (native_md5) {
        free(native_md5);
        native_md5 = NULL;
    }

    return ret;
}

static int rg_tipc_client_write_file(char *file_name, char *buf, int len)
{
    FILE *stream;
    int length, total_len = 0;
    char file[1500];

    if (!buf) {
        TIPC_DEBUG("buf is NULL!");
        return FAIL;
    }

    if (len == 0) {
        TIPC_DEBUG("len too short!");
        return FAIL;
    }

    if (!file_name) {
        TIPC_DEBUG("file name is NULL!");
        return FAIL;
    }

    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file) - 1, "/tmp/%s", file_name);
    stream = fopen(file, "ab");
    if (!stream) {
        perror("fopen error.");
        return FAIL;
    }

    length = fwrite(buf, 1, len, stream);
    if (length <= 0) {
        perror("fwrite error!");
        fclose(stream);
        return FAIL;
    }

    if (stream) {
        fclose(stream);
    }

    return SUCESS;
}

void main(int argc,char *argv[])
{
    int ret, sd, len, total_len = 0;
    unsigned int instance = 0;
    unsigned char mac[20], buf[1500], rm_cmd[128], file[1500];
    struct sockaddr_tipc server_addr, client_addr;
    socklen_t length = sizeof(client_addr);
    struct timeval timeout={3000, 0};
    int wait_err;
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif

    if (argc != 3) {
        perror("Usage: rg_tipc_client_download [sn] [file name]\n");
        exit(1);
    }


    /*
     * Determine whether the files to be downloaded
     * exist in the TMP directory. if exist, stop
     * it. otherwise, continue.
     */
    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file) - 1, "/tmp/%s", argv[2]);
    if (access(file, F_OK) == 0) {
        TIPC_DEBUG("file exist!");
        ret = FAIL;
        goto end;
    }

    if (strlen(argv[1]) != 17 && !strchr(argv[1], ':')) {
        memset(mac,0,sizeof(mac));
        char num = 0;
        while(1){
            rg_sn_to_mac(argv[1], mac);
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
        instance = rg_mist_mac_2_nodeadd(argv[1]);
    }

    if (instance == 0) {
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    if (wait_for_server(SERVER_TYPE_DOWNLOAD, instance, 3000) == FAIL){
        TIPC_DEBUG("error");
        ret = FAIL;
        goto end;
    }

    sd = socket(AF_TIPC, SOCK_SEQPACKET, 0);
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
        perror("connect error");
        ret = FAIL;
        goto end;
    }

    /* send peer file's name */
    memset(buf, 0, sizeof(buf));
    memcpy(buf, argv[2], strlen(argv[2]));
    len = send(sd, buf, strlen(buf), 0);
    if (len != strlen(buf)) {
        perror("Client: send failed\n");
        ret = FAIL;
        goto end;
    }

//    /* 等待对端消息 */
//    wait_err = wait_for_msg(sd);
//    if (wait_err) {
//        perror("wait error.");
//        ret = FAIL;
//        goto end;
//    }

    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval));
    while (1) {
        memset(buf, 0, sizeof(buf));
        len = recv(sd, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("recv error.");
            ret = FAIL;
            goto end;
        }
        if (memcmp(buf, "@zhangyz$&", strlen("@zhangyz$&")) == 0) {
//            TIPC_DEBUG("LAST MESSAGE!!!!");
            break;
        }
        total_len += len;
        ret = rg_tipc_client_write_file(argv[2], buf, len);
        if (ret == FAIL) {
            TIPC_DEBUG("recv error!");
            break;
        }
//        TIPC_DEBUG("RECV-OK!    len %d    total_len %d", len, total_len);
    }

    ret = rg_tipc_client_md5_check(argv[2], buf, total_len);
    if (ret == FAIL) {
        TIPC_DEBUG("md5 check fail!");
        goto end;
    }
    printf("DOWNLOAD-OK\n");
    ret = SUCESS;
end:
    if (sd) {
        close(sd);
    }

    return ret;
}

