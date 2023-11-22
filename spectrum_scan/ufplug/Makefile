#编框架组件 只编译出.o 无需编译成 可执行文件
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

#拓展通配符 在此意为src下所有的.c
SRCS := $(wildcard *.c)
LIBS := $(wildcard *.a)
#替换符通配 就是把$(SRCS))中的所有.c替换成.o
OBJS := $(patsubst %.c,%.o,$(SRCS))

LDFLAGS += -fPIC  -L$(STAGING_DIR)/usr/lib -ljson-c -lubox -luci -lpthread -lubus -lufplug #-llib_c

UF_MODULE_SO := spectrumScan.so
EXECUTABLE := spectrumScan
PKG_ROOT_PATH_UF = $(STAGING_DIR)/usr/lib/ufplugins
PKG_EXEC_PATH_UF = $(STAGING_DIR)/usr/bin

# 拷贝依赖关系到指定文件
UF_ALL_FLAGS = $(if $(wildcard $(PKG_ROOT_PATH_UF)/.ldflags),$(shell cat $(PKG_ROOT_PATH_UF)/.ldflags))
UF_ALL_FLAGS += $(LDFLAGS)
UF_ALL_FLAGS := $(sort $(UF_ALL_FLAGS))

all: $(OBJS)
# 编译.o文件
	$(CC) -c $(CFLAGS) $(LDFLAGS) $(SRCS)
	$(CC) $(OBJS) $(LDFLAGS) -shared -o $(UF_MODULE_SO)
# # 拷贝目标文件到指定目录
# 	$(INSTALL_DIR) $(PKG_ROOT_PATH_UF)
# 	$(CP) $(CURDIR)/$(UF_MODULE_SO) $(PKG_ROOT_PATH_UF)