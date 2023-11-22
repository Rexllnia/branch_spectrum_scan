SRCS := rg_wds_misc.c rg_main.c rg_wds_dev.c rg_wds_ath.c rg_wds_gpio.c rg_wds_pair_assioc.c rg_wds_keep_live.c rg_wds_send_date.c \
		rg_wds_led_sync.c rg_wds_get_date.c rg_wds_info.c rg_wds_beacon.c rg_wds_version.c rg_wds_lock.c rg_wds_json.c rg_wds_protocl.c \
		rg_wds_recv_massage.c rg_wds_update.c rg_wds_pair_cmd.c rg_wds_pair_all.c
OBJS := $(SRCS:%.c=%.o)
SRCS_2 := rg_wds_send_massage.c
OBJS_2 := $(SRCS_2:%.c=%.o)
LDFLAGS += -L$(STAGING_DIR)/usr/lib
LIBS += -luci -lpthread -ljson-c -lrt
CFLAGS += -I$(STAGING_DIR)/usr/include/json-c
TARGET = rg_wds_gpio
All:$(OBJS) $(OBJS_2) firmware_to_bin.o rg_est_wds_sync.o rg_est_get_sync.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_wds_gpio $(OBJS)
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_wds_send_massage $(OBJS_2)
	#$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o firmware_to_bin firmware_to_bin.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_est_wds_sync rg_est_wds_sync.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_est_get_sync rg_est_get_sync.o
clean:
	rm -f *.o rg_wds
