

ELFNAME:=one_click_conn
TARGET_OBJ:=$(ELFNAME).o one_click_log.o
OUTPUT := $(ELFNAME).elf

VPATH = -I ../plugin/

STAG_LIB_PATH    := $(STAGING_DIR)/usr/lib

LDFLAGS   := -L $(STAG_LIB_PATH)

LIBS := -lunifyframe -ljson-c -luci -lwas -lrg_crypto  
.PHONY: all
all:$(TARGET_OBJ)
	$(CC) $^ -o  $(OUTPUT)  $(LDFLAGS) $(LIBS)

$(TARGET_OBJ):%.o:%.c
	$(CC) -c $(VPATH) $< -o $@
