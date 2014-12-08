CFLAGS = -std=c99
LIBS = -lldns
BINDIR = $(DESTDIR)/usr/bin
DEPS = Makefile debug.h
OBJS = dnsproxy.o

all: dnsproxy

%.o: %.c $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

dnsproxy: $(OBJS) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)

install: dnsproxy
	install -d $(BINDIR)
	install -m 755 dnsproxy $(BINDIR)

uninstall:
	rm -f $(BINDIR)/dnsproxy

clean:
	rm -f dnsproxy *.o

.PHONY: all clean install uninstall