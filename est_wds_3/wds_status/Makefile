TARGET := wds_status.so

CFLAGS += -fPIC -O2 -g
LIBS=-luci -ljson-c -lufplug


all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $^


$(TARGET): wds_status.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)


