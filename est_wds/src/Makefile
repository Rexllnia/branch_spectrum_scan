rg_wds: rg_wds.o
	$(CC) $(LDFLAGS) -L$(STAGING_DIR)/usr/lib -luci -lpcap -lpthread -ljson-c rg_wds.o -o  rg_wds_gpio
rg_wds.o: rg_wds.c
	$(CC) $(CFLAGS) -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/usr/include/json-c  -c rg_wds.c
clean:
	rm -f *.o rg_wds
