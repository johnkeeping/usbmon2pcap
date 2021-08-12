all:: usbmon2pcap

RM ?= rm -f

CFLAGS = -Wall -O2 -g -ggdb

PCAP_CFLAGS := $(shell pkg-config --cflags libpcap)
PCAP_LIBS := $(shell pkg-config --libs libpcap)

USBMON2PCAP_CFLAGS = $(CFLAGS) $(PCAP_CFLAGS)
USBMON2PCAP_LDFLAGS = $(LDFLAGS) $(PCAP_LIBS)

SOURCES = usbmon2pcap.c
OBJECTS = $(SOURCES:%.c=%.o)

$(OBJECTS): %.o: %.c
	$(CC) -c -o $@ $(USBMON2PCAP_CFLAGS) $^

usbmon2pcap: $(OBJECTS)
	$(CC) -o $@ $(USBMON2PCAP_CFLAGS) $^ $(USBMON2PCAP_LDFLAGS)

clean:
	$(RM) $(OBJECTS) usbmon2pcap

install: all
	$(INSTALL) -d $(DESTDIR)/usr/bin
	$(INSTALL) -m 0755 usbmon2pcap $(DESTDIR)/usr/bin/usbmon2pcap
