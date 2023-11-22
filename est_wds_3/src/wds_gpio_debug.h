#ifndef WDS_GPIO_DEBUG_H
#define WDS_GPIO_DEBUG_H

#include <libdebug/libdebug.h>

#define GPIO_DBG_FILE                   "/tmp/rg_wds_gpio.log"

/*∂®“Âdebug∫Í*/
extern int gpio_id;
#define GPIO_FILE(fmt, arg...) do { \
    dbg_logfile(gpio_id, fmt, ##arg);\
} while (0)

#define GPIO_DEBUG(fmt, arg...) do { \
    dbg_printf(gpio_id, DBG_LV_DEBUG, "Function %s: "fmt"\n", __FUNCTION__, ##arg);\
    printf("[%s:%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);\
} while (0)

#define GPIO_WARNING(fmt, arg...) do { \
    dbg_printf(gpio_id, DBG_LV_WARNING, "WARNING in %s [%d]: "fmt"\n", __FILE__, __LINE__, ##arg);\
    printf(fmt"\n", ##arg);\
} while (0)

#define GPIO_ERROR(fmt, arg...) do { \
    dbg_printf(gpio_id, DBG_LV_ERROR, "ERROR in %s [%d]: "fmt"\n", __FILE__, __LINE__, ##arg);\
    printf(fmt"\n", ##arg);\
} while (0)

#endif

