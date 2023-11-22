#ifndef _ONE_CC_H_
#define _ONE_CC_H_

#define OCC_DEBUG(format, ...) do {\
    UF_PLUG_DEBUG(g_intf, 0, "(%s %s %d)"format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);\
} while(0)

#define OCC_PROAM "one_click_conn.elf"

#endif /* _ONE_CC_H_ */