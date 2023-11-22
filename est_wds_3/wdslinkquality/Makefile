TARGET := wdslinkquality.so

CFLAGS += -fPIC -O2 -g
LIBS=-luci -ljson-c -lhiredis -lufplug


all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $^


$(TARGET): wdsLinkQuality.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)


