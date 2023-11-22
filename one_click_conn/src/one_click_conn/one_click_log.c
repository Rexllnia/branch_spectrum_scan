/*
 * OneCC_wake_log.c
 *
 *  Created on: 2019-10-26
 *      Author: ruijie
 */

#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include "one_click_log.h"

#define LOG_NAME_LEN       256
#define LOG_SIZE_DEFAULT   100
#define LOG_NAME_DEFAULT   "/tmp/OneClickConn/one_cclog.log"
#define LOG_DIR_DEFAULT    "/tmp/OneClickConn"

static pthread_mutex_t g_log_file_lock;                     /* 日志文件操作互斥锁 */
static char g_log_name[LOG_NAME_LEN] = LOG_NAME_DEFAULT;    /* 日志文件名 */
static char g_log_dir[LOG_NAME_LEN] = LOG_DIR_DEFAULT;      /* 日志文件路径 */
static unsigned int g_log_file_size = LOG_SIZE_DEFAULT;     /* 日志文件大小：单位KB，默认100KB */
static log_level_t g_log_level = LOG_ALL;                   /* 默认日志等级 */
static int g_log_pid = 0;                                   /* 调用进程的PID */

int onecc_log_init(const char *log_name, unsigned int log_size, log_level_t level)
{

    /* 参数检查 */
    if (log_name == NULL || log_size == 0) {
        fprintf(stderr, "liblog_init() failed, param error in %s on %d lines\n", __FILE__, __LINE__);
        return -1;
    }

    /* log_file_name */
    memset(g_log_name, 0, LOG_NAME_LEN);
    snprintf(g_log_name, LOG_NAME_LEN, "%s", log_name);

    /* log_file_dir */
    memset(g_log_dir, 0, LOG_NAME_LEN);
    snprintf(g_log_dir, strrchr(g_log_name, '/') - g_log_name + 1, "%s", g_log_name);

    /* log_file_size */
    g_log_file_size = log_size;

    /* log_level */
    g_log_level = level;

    /* process pid */
    g_log_pid = getpid();

    return 0;
}

int onecc_log(log_level_t level, char *fmt, ...)
{
#if 0
    int ret;
#endif
    FILE *fp;
    va_list args;
    struct tm tm;
    struct stat st;
    struct timeval tv;
    char g_log_file_name_old[LOG_NAME_LEN];

    pthread_mutex_lock(&g_log_file_lock);
    if (g_log_level < level) {
        pthread_mutex_unlock(&g_log_file_lock);
        return -1;
    }
    if (access(g_log_dir, F_OK) == -1) {
        mkdir(g_log_dir, S_IRWXU | S_IRWXG | S_IRWXO);
#if 0
        ret = mkdir(g_log_dir, S_IRWXU | S_IRWXG | S_IRWXO);
        if (ret == -1) {
            if (errno != EEXIST) {
                /* printf("Failed to create directory %s, errno=%d, %s.\n",
                   g_log_dir, errno, strerror(errno));*/
                /* 打印到syslog中，可以用logread查看 */
                int priority = L_NOTICE;
                openlog(name, 0, LOG_DAEMON);
                va_start(vl, format);
                vsyslog(log_class[priority], format, vl);
                va_end(vl);
                closelog();
                return -1;
            }
        }
#endif
    }
    if (stat(g_log_name, &st) == 0) {
        if (st.st_size > (g_log_file_size * 1024) / 2) {
            memset(g_log_file_name_old, 0, LOG_NAME_LEN);
            snprintf(g_log_file_name_old, LOG_NAME_LEN, "%s.old", g_log_name);
            rename(g_log_name, g_log_file_name_old);
        }
    }
    fp = fopen(g_log_name, "a");
    if (fp != NULL) {
        gettimeofday(&tv, NULL);
        localtime_r(&tv.tv_sec, &tm);
        fprintf(fp, "[%d][%04d-%02d-%02d %02d:%02d:%02d]",
                g_log_pid,
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec);
        va_start(args, fmt);
        (void)vfprintf(fp, fmt, args);
        va_end(args);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_log_file_lock);

    return 0;
}

