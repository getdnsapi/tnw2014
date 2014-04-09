LIBS     = -lgetdns
LIBS_DIR = -L/usr/local/lib
CFLAGS   = -I/usr/local/include -g -Wall
LDFLAGS     := $(LIBS_DIR) $(LIBS)

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

all: getdns_dane_getkey getdns_dane_encode

getdns_dane_getkey: getdns_dane_getkey.o
	$(CC) $(OBJS) $< $(LDFLAGS) -o $@

getdns_dane_encode: getdns_dane_encode.o
	$(CC) $(OBJS) $< $(LDFLAGS) -o $@

clean:
	rm -f *.o getdns_dane_encode getdns_dane_getkey
