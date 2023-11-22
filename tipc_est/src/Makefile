LIBS +=-ljson-c -lpthread -lssl -lcrypto -lrg_crypto
OBJ_REDIS :=
ifeq ($(CONFIG_REDIS_SUPPORT),y)
LIBS += -lrgproto -lhiredis
OBJ_REDIS := rg_tipc_redis.o
endif
all:tipc-config.o rg_tipc_misc.o rg_tipc_mac_to_nodeadd.o rg_tipc_crypto.o rg_tipc_server_shell.o rg_tipc_client_shell.o client_tipc.o server_tipc.o \
rg_tipc_server_ping.o rg_tipc_client_ping.o rg_tipc_server_upgrade.o rg_tipc_client_upgrade.o rg_tipc_server_download.o rg_tipc_client_download.o $(OBJ_REDIS)
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o tipc-config tipc-config.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_mac_to_nodeadd rg_tipc_mac_to_nodeadd.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_server_shell rg_tipc_misc.o rg_tipc_crypto.o $(OBJ_REDIS) rg_tipc_server_shell.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_client_shell rg_tipc_misc.o rg_tipc_crypto.o rg_tipc_client_shell.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_server_ping rg_tipc_misc.o rg_tipc_server_ping.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_client_ping rg_tipc_misc.o rg_tipc_client_ping.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_server_upgrade rg_tipc_misc.o rg_tipc_server_upgrade.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_client_upgrade rg_tipc_misc.o rg_tipc_client_upgrade.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_server_download rg_tipc_misc.o rg_tipc_server_download.o
	$(CC) -Wall -Werror $(LDFLAGS) $(LIBS) $(CFLAGS) -o rg_tipc_client_download rg_tipc_misc.o rg_tipc_client_download.o
clean:
	rm -f *.o
