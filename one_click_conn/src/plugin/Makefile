include $(TOPDIR)/rules.mk
include $(TOPDIR)/.config
LIBS +=-fPIC -ljson-c -llib_c\
	$(if $(CONFIG_RG_FRAME_C_CMD), -lufplug)

STAG_INCL_PATH   := $(STAGING_DIR)/usr/include
STAG_LIB_PATH    := $(STAGING_DIR)/usr/lib

# export INFLAGS   := -I $(STAG_INCL_PATH)
# export LDFLAGS   := -L $(STAG_LIB_PATH)

INFLAGS   := -I $(STAG_INCL_PATH)
LDFLAGS   := -L $(STAG_LIB_PATH)

LINKFLAGS += -Xlinker -rpath=$(STAG_LIB_PATH)
LINKFLAGS += -shared

# Must be a unify module !!!
BUILD_PATH +=main:
BUILD_PATH +=plugin:.

# For unify module
BUILD_DIRS = $(subst :, ,$(BUILD_PATH))
SRCPATH = $(foreach dir, $(BUILD_DIRS), $(wildcard $(dir)/*.c))
SRCNAMES = $(notdir $(SRCPATH))
OBJS = $(patsubst %.c, %.o, $(SRCNAMES))



.PHONY:all
all:$(OBJS) $(ONE_CC_MODULE_SO)
$(OBJS):%.o:%.c
	echo "building objects .........."
	echo "objects ::$(CC) -c CFLAGS=$(CFLAGS) LDFLAGS=$(LDFLAGS) LINKFLAGS=$(LINKFLAGS) LIBS=$(LIBS)"
	$(CC) -c $(LDFLAGS) $(LINKFLAGS) $(LIBS) $< -o $@

$(ONE_CC_MODULE_SO):$(OBJS)
	@echo "building so ........"
	echo "building ::$(CC) -c CFLAGS=$(CFLAGS) LDFLAGS=$(LDFLAGS) LINKFLAGS=$(LINKFLAGS) LIBS=$(LIBS)"
	echo "OBJ::::$(OBJS)"
	$(CC)  $(LDFLAGS) $(LINKFLAGS)  $(LIBS) $^ -o $(ONE_CC_MODULE_SO)
	chmod 755 $(ONE_CC_MODULE_SO)

clean:
	rm -rf $(ONE_CC_MODULE_SO) $(OBJS)