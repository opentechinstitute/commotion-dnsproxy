CFLAGS += -std=c99 -DUSESYSLOG
LIBS = -lldns
BINDIR=$(DESTDIR)/usr/bin

dnsproxy: daemon.c debug.h
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

all: dnsproxy

install: dnsproxy
	install -d $(BINDIR)
	install -m 755 dnsproxy $(BINDIR)

uninstall:
	rm -f $(BINDIR)/dnsproxy

clean:
	rm -f dnsproxy

.PHONY: all clean install uninstall