# Define EVDIR=/foo/bar if your libev header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
EVDIR=$(HOME)/local/libev

# Define GNUTLSDIR=/foo/bar if your gnutls header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
#GNUTLSDIR=/usr

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')
uname_O := $(shell sh -c 'uname -o 2>/dev/null || echo not')
uname_R := $(shell sh -c 'uname -r 2>/dev/null || echo not')
uname_P := $(shell sh -c 'uname -p 2>/dev/null || echo not')

# CFLAGS and LDFLAGS are for the users to override from the command line.
CFLAGS	= -g 
LDFLAGS	= 

PREFIX = $(HOME)/local/liboi

CC = gcc
AR = ar
RM = rm -f
RANLIB = ranlib

CFLAGS  += -fPIC -I.
LDOPT    = -shared
SUFFIX   = so
SONAME   = -Wl,-soname,$(OUTPUT_LIB)

ifeq ($(uname_S),Linux)
	CFLAGS += -D__linux=1
endif
ifeq ($(uname_S),FreeBSD)
	CFLAGS += -D__freebsd=1
endif
ifeq ($(uname_S),SunOS)
	CFLAGS += -D__solaris=1
endif
ifeq ($(uname_S),HP-UX)
	CFLAGS += -D__hpux=1
endif
ifeq ($(uname_S),Darwin)
	CFLAGS += -D__darwin=1
	LDOPT   = -dynamiclib
	SONAME  = -current_version $(VERSION) -compatibility_version $(VERSION)
	SUFFIX  = dylib
endif

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
OUTPUT_LIB=$(NAME).$(SUFFIX).$(VERSION)
OUTPUT_A=$(NAME).a

LINKER=$(CC) $(LDOPT)

TESTS = test/test_ping_pong_tcp_secure \
				test/test_ping_pong_unix_secure \
				test/test_ping_pong_tcp_clear \
				test/test_ping_pong_unix_clear \
				test/test_connection_interruption_tcp_secure \
				test/test_connection_interruption_unix_secure \
				test/test_connection_interruption_tcp_clear \
				test/test_connection_interruption_unix_clear \
				test/echo

all: $(OUTPUT_LIB) $(OUTPUT_A) $(TESTS)

$(OUTPUT_LIB): $(OBJ) 
	$(LINKER) -o $(OUTPUT_LIB) $(OBJ) $(SONAME) $(LDFLAGS)

$(OUTPUT_A): $(OBJ)
	$(AR) cru $(OUTPUT_A) $(OBJ)
	$(RANLIB) $(OUTPUT_A)

.c.o:
	$(CC) -c ${CFLAGS} $<

${OBJ}: ${DEP}

FAIL=echo "FAIL"
PASS=echo "PASS"

test: $(TESTS) /tmp/oi_fancy_copy_src
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
	rm -f ${OBJ} $(OUTPUT_A) $(OUTPUT_LIB) $(NAME)-${VERSION}.tar.gz 
	rm -rf test/test_* test/fancy_copy test/echo

install: $(OUTPUT_LIB) $(OUTPUT_A)
	@echo INSTALLING ${OUTPUT_A} and ${OUTPUT_LIB} to ${PREFIX}/lib
	install -d -m755 ${PREFIX}/lib
	install -d -m755 ${PREFIX}/include
	install -m644 ${OUTPUT_A} ${PREFIX}/lib
	install -m755 ${OUTPUT_LIB} ${PREFIX}/lib
	ln -sfn $(PREFIX)/lib/$(OUTPUT_LIB) $(PREFIX)/lib/$(NAME).so
	@echo INSTALLING headers to ${PREFIX}/include
	install -m644 oi*.h ${PREFIX}/include 

uninstall:
	@echo REMOVING so from ${PREFIX}/lib
	rm -f ${PREFIX}/lib/${NAME}.*
	@echo REMOVING headers from ${PREFIX}/include
	rm -f ${PREFIX}/include/oi_*.h

.PHONY: all options clean clobber install uninstall test 
