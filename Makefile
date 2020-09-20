CC=gcc
CFLAGS=-O -Wall -g -lpthread -lcrypto -lssl 

all: scanner

scanner: src/external/crc32c.c src/external/winnowing.c src/scanner.c 
	 $(CC) -o scanner src/scanner.c $(CFLAGS)

install:
	cp scanner /usr/bin

clean:
	rm -f scanner

distclean: clean

