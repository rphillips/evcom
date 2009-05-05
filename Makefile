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

TESTS = test/test_ping_pong_tcp_secure \
				test/test_ping_pong_unix_secure \
				test/test_ping_pong_tcp_clear \
				test/test_ping_pong_unix_clear \
				test/test_connection_interruption_tcp_secure \
				test/test_connection_interruption_unix_secure \
				test/test_connection_interruption_tcp_clear \
				test/test_connection_interruption_unix_clear \
				test/echo

all: $(OUTPUT_A) $(TESTS)

$(OUTPUT_A): $(OBJ)
	$(AR) cru $(OUTPUT_A) $(OBJ)
	$(RANLIB) $(OUTPUT_A)

.c.o:
	$(CC) -c ${CFLAGS} $<

${OBJ}: ${DEP}

FAIL=echo "FAIL"
PASS=echo "PASS"

test: $(TESTS)
	@for i in test/test_*; do \
		if [ ! -d $$i ]; then \
			echo "$$i: ";	\
			$$i && $(PASS) || $(FAIL); \
		fi \
	done 
	@echo "timeouts: "
	@test/timeout.rb

test/test_ping_pong_tcp_secure: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=1

test/test_ping_pong_unix_secure: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=1

test/test_ping_pong_tcp_clear: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

test/test_ping_pong_unix_clear: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=0

test/test_connection_interruption_tcp_secure: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=1

test/test_connection_interruption_unix_secure: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=1

test/test_connection_interruption_tcp_clear: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

test/test_connection_interruption_unix_clear: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=0

test/echo: test/echo.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

clean:
	rm -rf test/test_* test/fancy_copy test/echo
	rm -f $(OUTPUT_A) *.o

.PHONY: all clean test 
