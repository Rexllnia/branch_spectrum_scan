
TARGET := wds_list_all.so

CFLAGS += -fPIC -O2 -g
LIBS=-luci -ljson-c -lhiredis -lufplug

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $^


$(TARGET): wds_list_all.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

