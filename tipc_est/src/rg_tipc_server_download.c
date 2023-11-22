#include "rg_tipc.h"
#include<sys/resource.h>
char g_file_name[1500];
bool g_tipc_fini_flag = false;
int new_socket_cnt = 0;
pthread_t file_download_sub_thread[TIPC_QUEUE_MAXCNT];
pthread_mutex_t mtx_tipc_dl_lock = PTHREAD_MUTEX_INITIALIZER;

void *rg_tipc_file_download_process(void *param)
{
    unsigned char buf[1500], file_name[128], md5_cmd[128], dl_file_name[1532];
    FILE *stream;
    char *md5_val;
    int size, socket_fd, len, slen;
    struct sockaddr_tipc client_addr;
    socklen_t length = sizeof(client_addr);
    int total_len = 0;
    struct timeval timeout={5, 0};

    /*
     * detach self thread, in order to release self thread resource.
     */
    pthread_detach(pthread_self());

    if (!param) {
        TIPC_DEBUG("socket fd is NULL!");
        goto exit;
    }

    if (strlen(g_file_name) == 0) {
        TIPC_DEBUG("g_file_name is NULL!");
        goto exit;
    }
    memset(dl_file_name, 0, sizeof(dl_file_name));
    snprintf(dl_file_name, sizeof(dl_file_name), "/tmp/%s", g_file_name);
    if (access(dl_file_name, F_OK) != 0) {
        TIPC_DEBUG("file no exist[%s].", dl_file_name);
        goto exit;
    }

    socket_fd = *(int *)param;
    TIPC_DEBUG("[%d]File's name <%s>", socket_fd, g_file_name);

//    tmp_softversion = rg_tipc_execute_buf(GET_TMP_SOFTVERSION);
//    if (!tmp_softversion) {
//        TIPC_DEBUG("Execute cmd[%s] error!", GET_TMP_SOFTVERSION);
//        goto exit;
//    }
    memset(file_name, 0, sizeof(file_name));
    snprintf(file_name, sizeof(file_name), "/tmp/%s", g_file_name);
    /* if tar.gz exist, send stream to client */
    stream = fopen(file_name, "rb");
    if (stream == NULL) {
        TIPC_DEBUG("filename %s open error.", file_name);
        /* Prevent bad file descriptors */
        g_tipc_fini_flag = true;
        goto exit;
    }
    /* Prevent bad file descriptors */
    g_tipc_fini_flag = true;

    /*
     * send the md5sum and total length
     */
    memset(md5_cmd, 0, sizeof(md5_cmd));
    snprintf(md5_cmd, sizeof(md5_cmd) - 1, TIPC_MD5_CMD, g_file_name);
    md5_val = rg_tipc_execute_buf(md5_cmd);
    if (!md5_val) {
        TIPC_DEBUG("Execute cmd[%s] error!", TIPC_MD5_CMD);
        goto exit;
    }

    while (1) {
        memset(buf, 0, sizeof(buf));
        if ((len = fread(buf, 1, sizeof(buf), stream)) <= 0) {
            TIPC_DEBUG("READ-END.[%d]", socket_fd);
            break;
        }
        total_len += len;

        slen = send(socket_fd, buf, len, 0);
        if (slen != len) {
            perror("send error.");
            continue;
        }
        usleep(20 * 1000);
        //TIPC_DEBUG("send suc[%d].    len %d    total_len %d", socket_fd, len, total_len);
    }

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "%s%d#%s", TIPC_UPGRD_FINI_STR, total_len, md5_val);
    slen = send(socket_fd, buf, strlen(buf), 0);
    if (slen != strlen(buf)) {
        perror("send error.");
        goto exit;
    }

    TIPC_DEBUG("SEND-OK[%d].", socket_fd);

exit:
//    if (tmp_softversion) {
//        free(tmp_softversion);
//        tmp_softversion = NULL;
//    }
    if (md5_val) {
        free(md5_val);
        md5_val = NULL;
    }
    if (stream) {
        fclose(stream);
    }
    if (socket_fd) {
        shutdown(socket_fd, 2);
        close(socket_fd);
    }

    new_socket_cnt--;
    return NULL;
}

int rg_tipc_server_download_process(void)
{
    unsigned char mac[20], native_sn[16], buf[BUF_SIZE];
    unsigned int instant = 0;
    struct sockaddr_tipc server_addr;
    struct sockaddr_tipc client_addr;
    socklen_t length = sizeof(client_addr);
    int socket_fd, ret, len, r, i;
    int new_socket_fd;
    struct timeval timeout={4, 0};
    fd_set fds;
    struct timeval tv;

begin:
    memset(mac,0,sizeof(mac));
    rg_misc_read_file("/proc/rg_sys/sys_mac", mac, sizeof(mac) - 1);
    instant = rg_mist_mac_2_nodeadd(mac);
    if (instant == 0) {
        TIPC_DEBUG("error exit instant %d", instant);
        goto begin;
    }

    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAMESEQ;
    server_addr.addr.nameseq.type = SERVER_TYPE_DOWNLOAD;
    server_addr.addr.nameseq.lower = instant;
    server_addr.addr.nameseq.upper = instant;
    server_addr.scope = TIPC_ZONE_SCOPE;

    socket_fd = socket(AF_TIPC, SOCK_SEQPACKET, 0);

    if (0 != bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))){
        perror("Server: failed to bind port name.");
        sleep(1);
        close(socket_fd);
        goto begin;
    }

    if (listen(socket_fd, TIPC_QUEUE_MAXCNT) < 0) {
        perror("listen error.");
        close(socket_fd);
        return FAIL;
    }
    /* Prevent bad file descriptors */
    g_tipc_fini_flag = true;

    while (1) {
        /* select: non-blocking wait for client link. */
        FD_ZERO(&fds);
        FD_SET(socket_fd, &fds);
        tv.tv_sec  = 5; /* timeout 5s */
        tv.tv_usec = 0;
        r = select(socket_fd + 1, &fds, 0, 0, &tv);
        if (g_tipc_fini_flag == true && r > 0 && FD_ISSET(socket_fd, &fds)) {
            new_socket_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &length);
            if (new_socket_fd < 0) {
                perror("accept error.");
                continue;
            }
            /* Prevent bad file descriptors */
            g_tipc_fini_flag = false;
            TIPC_DEBUG("accpet[%d]", new_socket_fd);
        } else {
            continue;
        }

        memset(buf, 0, sizeof(buf));
        len = recv(new_socket_fd, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("recv error.");
            close(new_socket_fd);
            continue;
        }
        //TIPC_DEBUG("buf %s", buf);

        if (new_socket_cnt >= TIPC_QUEUE_MAXCNT) {
            TIPC_DEBUG("Up to max thread count!!!");
            close(new_socket_fd);
            continue;
        }
        memset(g_file_name, 0, sizeof(g_file_name));
        memcpy(g_file_name, buf, len);

        pthread_mutex_lock(&mtx_tipc_dl_lock);
        if (pthread_create(&file_download_sub_thread[new_socket_cnt++], NULL,
                                rg_tipc_file_download_process, (void *)&new_socket_fd) != 0) {
            TIPC_DEBUG("Create thread fail!");
            new_socket_cnt--;
            close(new_socket_fd);
            continue;
        }
        TIPC_DEBUG("Create thread[%d] suc.", new_socket_cnt);
        pthread_mutex_unlock(&mtx_tipc_dl_lock);
    }

    if (new_socket_fd) {
        close(new_socket_fd);
    }
    if (socket_fd) {
        close(socket_fd);
    }

    return SUCESS;
}

int main()
{
    int ret;
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif
    ret = rg_tipc_server_download_process();
    if (ret == FAIL) {
        TIPC_DEBUG("fail!");
        return FAIL;
    }

    return SUCESS;
}
