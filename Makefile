# Define EVDIR=/foo/bar if your libev header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
EVDIR=$(HOME)/local/libev

# Define GNUTLSDIR=/foo/bar if your gnutls header and library files are in
# /foo/bar/include and /foo/bar/lib directories.
#
# Comment out the following line to disable TLS
GNUTLSDIR=/usr

# CFLAGS and LDFLAGS are for the users to override from the command line.
CFLAGS	= -g -I. -Wall -Werror -Wextra
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
	CFLAGS += -I$(GNUTLSDIR)/include -DEVNET_HAVE_GNUTLS=1
	LDFLAGS += -L$(GNUTLSDIR)/lib
	LDFLAGS += -lgnutls
endif

DEP = evnet.h
SRC = evnet.c
OBJ = ${SRC:.c=.o}

NAME=libevnet
OUTPUT_A=$(NAME).a

all: $(OUTPUT_A) 

$(OUTPUT_A): $(OBJ)
	$(AR) cru $(OUTPUT_A) $(OBJ)
	$(RANLIB) $(OUTPUT_A)

.c.o:
	$(CC) -c ${CFLAGS} $<

${OBJ}: ${DEP}

FAIL=ruby -e 'puts "\033[1;31m FAIL\033[m"'
PASS=ruby -e 'puts "\033[1;32m PASS\033[m"'

test: test/test test/echo test/timeout.rb
	@echo test.c
	@test/test > /dev/null && $(PASS) || $(FAIL)
	@echo timeout.rb
	@test/timeout.rb

test/test: test/test.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

test/echo: test/echo.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

clean:
	rm -rf test/test test/echo
	rm -f $(OUTPUT_A) *.o

.PHONY: all clean test 
