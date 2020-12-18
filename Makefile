CC=gcc
CFLAGS=-O -Wall -g -lpthread -lcrypto -lssl 
VERSION=`./scanner -h 2>&1  | head -n 1 | cut -d"-" -f2`

all: clean scanner deb

scanner: src/external/crc32c.c src/external/winnowing.c src/scanner.c 
	 $(CC) -o scanner src/scanner.c $(CFLAGS)

arm: src/external/crc32c.c src/external/winnowing.c src/scanner.c 
	 $(CC) -DCRC32_SOFTWARE_MODE -o scanner src/scanner.c $(CFLAGS) 

install:
	cp scanner /usr/bin

clean:
	rm -f scanner *deb

distclean: clean

deb:
	$(CC) -o scanner src/scanner.c $(CFLAGS)
	sed -i "s/Version:.*/Version: $(VERSION)/g" pkg/DEBIAN/control
	cp -vax scanner pkg/usr/bin
	dpkg-deb --build pkg
	mv pkg.deb scanoss-scanner-$(VERSION)_amd64.deb
