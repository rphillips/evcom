# Define EVDIR=/foo/bar if your libev header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
EVDIR=$(HOME)/local/libev

# Define GNUTLSDIR=/foo/bar if your gnutls header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
#
# Comment out the following line to disable TLS
GNUTLSDIR=/usr

# CFLAGS and LDFLAGS are for the users to override from the command line.
CFLAGS	= -g -I. -Wall 
LDFLAGS	= 

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
	LDFLAGS += -lgnutls
endif

DEP = evnet.h
SRC = evnet.c
OBJ = ${SRC:.c=.o}

VERSION = 0.1
NAME=libevnet
OUTPUT_A=$(NAME).a

TESTS = test/test \
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
	@echo test.c
	@test/test > /dev/null && $(PASS) || $(FAIL)
	@echo timeout.rb
	@test/timeout.rb

test/test: test/test.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

test/echo: test/echo.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

clean:
	rm -rf test/test test/echo
	rm -f $(OUTPUT_A) *.o

.PHONY: all clean test 
