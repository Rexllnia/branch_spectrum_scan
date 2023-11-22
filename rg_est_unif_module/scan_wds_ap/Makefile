TARGET := scan_wds_ap.so

CFLAGS += -fPIC -O2 -g
LIBS=-luci -ljson-c -lufplug

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $^


$(TARGET): scan_wds_ap.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)


