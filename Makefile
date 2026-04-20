CC=gcc
CFLAGS=-Wall -O2
LIBS=-lcrypto -lgssapi -lkrb5

all: sfc-client sfc-server

sfc-client:
	$(CC) $(CFLAGS) sfc-client.c common.c -o sfc-client $(LIBS)

sfc-server:
	$(CC) $(CFLAGS) sfc-server.c common.c -o sfc-server $(LIBS)

clean:
	rm -f sfc-client sfc-server received.out
