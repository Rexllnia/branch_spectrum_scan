#编框架组件 只编译出.o 无需编译成 可执行文件
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/.config

#拓展通配符 在此意为src下所有的.c
SRCS := $(wildcard *.c)
LIBS := $(wildcard *.a)
#替换符通配 就是把$(SRCS))中的所有.c替换成.o
OBJS := $(patsubst %.c,%.o,$(SRCS))

LDFLAGS += -L$(STAGING_DIR)/usr/lib -ljson-c -lubox -luci -lpthread -lubus -ldebug -lufplug -lunifyframe
ifeq ($(CONFIG_SPCTRM_SCN_REDBS_ENABLE),y)
LDFLAGS += -lhiredis
endif
PKG_ROOT_PATH_UF = $(STAGING_DIR)/usr/lib/ufplugins
PKG_EXEC_PATH_UF = $(STAGING_DIR)/usr/bin

# 拷贝依赖关系到指定文件
UF_ALL_FLAGS = $(if $(wildcard $(PKG_ROOT_PATH_UF)/.ldflags),$(shell cat $(PKG_ROOT_PATH_UF)/.ldflags))
UF_ALL_FLAGS += $(LDFLAGS)
UF_ALL_FLAGS := $(sort $(UF_ALL_FLAGS))

CC += -g -fno-limit-debug-info -fsanitize=address -fno-omit-frame-pointer -fsanitize=leak 

ifeq ($(CONFIG_SPECTRUM_SCAN24),y)	
EXTRA_FLAGS += -DSPCTRM_SCN24
endif
ifeq ($(CONFIG_SPECTRUM_SCAN_OLD),y)	
EXTRA_FLAGS += -DSPCTRM_SCN_OLD
endif
all: $(OBJS)
# 编译.o文件
	$(CC) -c $(CFLAGS) $(LDFLAGS) $(EXTRA_FLAGS) $(SRCS)
	$(CC) $(OBJS) $(LDFLAGS) $(EXTRA_FLAGS) $(LIBS)  -o spectrum_scan.elf

