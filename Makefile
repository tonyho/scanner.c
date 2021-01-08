CC=gcc
# Enable all compiler warnings. 
CCFLAGS= -fPIC -g -Wall -Werror -std=gnu99 -I./inc -I./external/inc

# Linker flags
LDFLAGS=-lpthread -lcrypto -lssl -lcurl
LIBFLAGS=-O -g -Wall -std=gnu99 -fPIC -c

VERSION=`./scanner -h 2>&1  | head -n 1 | cut -d"-" -f2`

SOURCES_SCANNER=$(wildcard src/*.c) $(wildcard src/**/*.c)  $(wildcard external/*.c) $(wildcard external/**/*.c)
OBJECTS_SCANNER=$(SOURCES_SCANNER:.c=.o)

SOURCES_LIB=$(filter-out src/main.c, $(SOURCES_SCANNER))
OBJECTS_LIB=$(SOURCES_LIB:.c=.o)

TARGET_SCANNER=scanner
TARGET_LIB=lib
TARGET_NOINTEL=no_intel

LIB_NAME=libscanner.so
BIN_NAME=scanner


$(TARGET_NOINTEL): CCFLAGS += -DCRC32_SOFTWARE_MODE

ifeq ("$(wildcard /usr/lib/x86_64-linux-gnu/libcurl.so)","")
$(warning  (WARNING Please install libcurl before build the project. Follow the instructions in README))
endif

all: clean scanner deb

$(TARGET_SCANNER): $(OBJECTS_SCANNER)
	$(CC) -g -o $(BIN_NAME) $^ $(LDFLAGS) 

$(TARGET_LIB): $(OBJECTS_LIB)
	$(CC) -g -o $(LIB_NAME) $^ $(LDFLAGS) -shared -Wl,-soname,libscanner.so

$(TARGET_NOINTEL): $(OBJECTS_SCANNER)
	$(CC) -g -o $(BIN_NAME) $^ $(LDFLAGS) 


.PHONY: scanner lib no_intel

%.o: %.c
	$(CC) $(CCFLAGS) -o $@ -c $<

install:$(BIN_NAME)
	cp $(BIN_NAME) /usr/bin
install_lib:$(LIB_NAME)
	cp $(LIB_NAME) /usr/lib
	mkdir -p /usr/include/scanner && cp inc/scanner.h /usr/include/scanner
clean_build:
	rm -f src/*.o src/**/*.o external/src/*.o external/src/**/*.o    

clean: clean_build
	rm -f $(BIN_NAME) $(LIB_NAME) *deb

distclean: clean

deb: $(TARGET_SCANNER)
	sed -i "s/Version:.*/Version: $(VERSION)/g" pkg/DEBIAN/control
	cp -vax scanner pkg/usr/bin
	dpkg-deb --build pkg
	mv pkg.deb scanoss-scanner-$(VERSION)_amd64.deb
	

