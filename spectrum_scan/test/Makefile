#编框架组件 只编译出.o 无需编译成 可执行文件
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

#拓展通配符 在此意为src下所有的.c
SRCS := $(wildcard *.c)
LIBS := $(wildcard *.a)
#替换符通配 就是把$(SRCS))中的所有.c替换成.o
OBJS := $(patsubst %.c,%.o,$(SRCS))

LDFLAGS +=  -L$(STAGING_DIR)/usr/lib -ljson-c -lubox -luci -lpthread -lubus -ldebug -lufplug -lunifyframe

EXECUTABLE := test
PKG_ROOT_PATH_UF = $(STAGING_DIR)/usr/lib/ufplugins
PKG_EXEC_PATH_UF = $(STAGING_DIR)/usr/bin

# 拷贝依赖关系到指定文件
UF_ALL_FLAGS = $(if $(wildcard $(PKG_ROOT_PATH_UF)/.ldflags),$(shell cat $(PKG_ROOT_PATH_UF)/.ldflags))
UF_ALL_FLAGS += $(LDFLAGS)
UF_ALL_FLAGS := $(sort $(UF_ALL_FLAGS))

CC += -g -fno-limit-debug-info -fsanitize=address -fno-omit-frame-pointer -fsanitize=leak 

all: $(OBJS)
# 编译.o文件
	$(CC)  -c $(CFLAGS) $(LDFLAGS) $(SRCS) 
	$(CC) $(OBJS) $(LDFLAGS) $(LIBS) -o test.elf

