#ifndef _OCC_LOG_H_
#define _OCC_LOG_H_

/*
 * onecc_log.h
 *
 *  Created on: 2019-10-26
 *      Author: ruijie
 */

#include <stdio.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/time.h>

typedef enum log_level_e {
    LOG_ERROR1   = 0,
    LOG_WARNING1 = 1,
    LOG_INFO1    = 2,
    LOG_DEBUG1   = 3,
    LOG_ALL
} log_level_t;

#define OneCC_ERROR(fmt, arg...) do { \
    onecc_log(LOG_ERROR1, " %s %s() [%d] [ERROR] "fmt, __FILE__, __func__, __LINE__, ##arg); \
} while (0)

#define OneCC_WARNING(fmt, arg...) do { \
    onecc_log(LOG_WARNING1, " %s %s() [%d] [WARNING] "fmt, __FILE__, __func__, __LINE__, ##arg); \
} while (0)

#define OneCC_INFO(fmt, arg...) do { \
    onecc_log(LOG_INFO1, " %s %s() [%d] [INFO] "fmt, __FILE__, __func__, __LINE__, ##arg); \
} while (0)

#define OneCC_DEBUG(fmt, arg...) do { \
    onecc_log(LOG_DEBUG1, " %s %s() [%d] [DEBUG] "fmt, __FILE__, __func__, __LINE__, ##arg); \
} while (0)

int onecc_log_init(const char *log_name, unsigned int log_size, log_level_t level);
int onecc_log(log_level_t level, char *fmt, ...);

#endif /* _OCC_LOG_H_ */

