# Define EVDIR=/foo/bar if your libev header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
EVDIR=$(HOME)/local/libev

# Define GNUTLSDIR=/foo/bar if your gnutls header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
GNUTLSDIR=/usr

# CFLAGS and LDFLAGS are for the users to override from the command line.
CFLAGS	= -g -I.
LDFLAGS	= 

PREFIX = $(HOME)/local/liboi

CC = gcc
AR = ar
RANLIB = ranlib

ifdef EVDIR
	CFLAGS += -I$(EVDIR)/include
	LDFLAGS += -L$(EVDIR)/lib
endif
LDFLAGS += -lev

ifdef GNUTLSDIR
	CFLAGS += -I$(GNUTLSDIR)/include -DHAVE_GNUTLS=1
	LDFLAGS += -L$(GNUTLSDIR)/lib
endif
LDFLAGS += -lgnutls

DEP = oi_socket.h
SRC = oi_socket.c
OBJ = ${SRC:.c=.o}

VERSION = 0.1
NAME=liboi
OUTPUT_A=$(NAME).a

TESTS = test/test_tcp \
				test/test_unix \
				test/echo

all: $(OUTPUT_A) $(TESTS)

$(OUTPUT_A): $(OBJ)
	$(AR) cru $(OUTPUT_A) $(OBJ)
	$(RANLIB) $(OUTPUT_A)

.c.o:
	$(CC) -c ${CFLAGS} $<

${OBJ}: ${DEP}

FAIL=ruby -e 'puts "\033[1;31m FAIL\033[m"'
PASS=ruby -e 'puts "\033[1;32m PASS\033[m"'

test: $(TESTS)
	@for i in test/test_*; do \
		if [ ! -d $$i ]; then \
			echo "$$i: ";	\
			$$i > /dev/null && $(PASS) || $(FAIL); \
		fi \
	done 
	@echo "timeouts: "
	@test/timeout.rb

test/test_tcp: test/test.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1

test/test_unix: test/test.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0

test/echo: test/echo.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

clean:
	rm -rf test/test_tcp test/test_unix test/echo
	rm -f $(OUTPUT_A) *.o

.PHONY: all clean test 
