SRCS := rg_wds_misc.c rg_main.c rg_wds_dev.c rg_wds_ath.c rg_wds_pair_assioc.c rg_wds_keep_live.c rg_wds_send_date.c \
		rg_wds_get_date.c rg_wds_info.c rg_wds_beacon.c rg_wds_version.c rg_wds_lock.c rg_wds_json.c rg_wds_protocl.c \
		rg_wds_recv_massage.c rg_wds_pair_cmd.c rg_wds_pair_all.c wds_gpio_callback.c automatic_range.c wds_pw_state.c rg_wds_frame.c
ifeq ($(WDS_REDIS_SUPPORT),y)
SRCS += rg_wds_redis.c
endif
OBJS := $(SRCS:%.c=%.o)

SRCS_2 := rg_wds_send_massage.c
OBJS_2 := $(SRCS_2:%.c=%.o)

LDFLAGS += -L$(STAGING_DIR)/usr/lib
LIBS += -luci -lpthread -ljson-c -lrt -ldebug -lubus -lubox -lwas -lrg_crypto -lunifyframe -lssl -lcrypto
ifeq ($(WDS_REDIS_SUPPORT),y)
LIBS += -lrgproto -lhiredis
endif

CFLAGS += -I$(STAGING_DIR)/usr/include/json-c

BUILD_CFLAGS :=
ifeq ($(WDS_REDIS_SUPPORT),y)
BUILD_CFLAGS += -DEST_SUPPORT_REDIS
endif

%.o: %.c
	$(CC) -c $(CFLAGS) $(BUILD_CFLAGS) $< -o $@

TARGET = rg_wds_gpio
All:$(OBJS) $(OBJS_2) firmware_to_bin.o rg_est_wds_sync.o rg_est_get_sync.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) -o rg_wds_gpio $(OBJS)
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) -o rg_wds_send_massage $(OBJS_2)
	#$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) -o firmware_to_bin firmware_to_bin.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) -o rg_est_wds_sync rg_est_wds_sync.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) -o rg_est_get_sync rg_est_get_sync.o
clean:
	rm -f *.o rg_wds
