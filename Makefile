# liboi - async madness
# See README file for copyright and license details.

include config.mk

DEP = oi.h
SRC = oi.c
ifeq ($(GNUTLSFLAGS),)
else
	SRC += rbtree.c oi_ssl_cache.c
	DEP += rbtree.h oi_ssl_cache.h
endif
OBJ = ${SRC:.c=.o}

VERSION = 0.1
NAME=liboi
OUTPUT_LIB=$(NAME).$(SUFFIX).$(VERSION)
OUTPUT_A=$(NAME).a

LINKER=$(CC) $(LDOPT)

all: options $(OUTPUT_LIB) $(OUTPUT_A)

options:
	@echo ${NAME} build options:
	@echo "CC       = ${CC}"
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "LDOPT    = ${LDOPT}"
	@echo "SUFFIX   = ${SUFFIX}"
	@echo "SONAME   = ${SONAME}"
	@echo

$(OUTPUT_LIB): $(OBJ) 
	@echo LINK $@
	@$(LINKER) -o $(OUTPUT_LIB) $(OBJ) $(SONAME) $(LIBS)

$(OUTPUT_A): $(OBJ)
	@echo AR $@
	@$(AR) cru $(OUTPUT_A) $(OBJ)
	@echo RANLIB $@
	@$(RANLIB) $(OUTPUT_A)

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: ${DEP}

test: test_rbtree
	./test_rbtree

test_rbtree: test_rbtree.o $(OUTPUT_A)
	@echo BUILDING test_rbtree
	@$(CC) $(CFLAGS) -o $@ $< $(OUTPUT_A)

examples: examples/echo

examples/echo: examples/echo.c $(OUTPUT_A) 
	@echo BUILDING examples/echo
	$(CC) -I. $(LIBS) $(CFLAGS) -lev -o $@ $^

clean:
	@echo CLEANING
	@rm -f ${OBJ} $(OUTPUT_A) $(OUTPUT_LIB) $(NAME)-${VERSION}.tar.gz 
	@rm -f test_rbtree  
	@rm -f examples/echo  

clobber: clean
	@echo CLOBBERING

dist: clean $(SRC)
	@echo CREATING dist tarball
	@mkdir -p ${NAME}-${VERSION}
	@cp -R doc examples LICENSE Makefile README config.mk ${SRC} ${DEP} ${NAME}-${VERSION}
	@tar -cf ${NAME}-${VERSION}.tar ${NAME}-${VERSION}
	@gzip ${NAME}-${VERSION}.tar
	@rm -rf ${NAME}-${VERSION}

install: $(OUTPUT_LIB) $(OUTPUT_A)
	@echo INSTALLING ${OUTPUT_A} and ${OUTPUT_LIB} to ${PREFIX}/lib
	install -d -m755 ${PREFIX}/lib
	install -d -m755 ${PREFIX}/include
	install -m644 ${OUTPUT_A} ${PREFIX}/lib
	install -m755 ${OUTPUT_LIB} ${PREFIX}/lib
	ln -sfn $(PREFIX)/lib/$(OUTPUT_LIB) $(PREFIX)/lib/$(NAME).so
	@echo INSTALLING headers to ${PREFIX}/include
	install -m644 oi.h ${PREFIX}/include 

uninstall:
	@echo REMOVING so from ${PREFIX}/lib
	rm -f ${PREFIX}/lib/${NAME}.*
	@echo REMOVING headers from ${PREFIX}/include
	rm -f ${PREFIX}/include/oi.h

upload_website:
	scp -r doc/index.html doc/icon.png rydahl@tinyclouds.org:~/web/public/liboi

.PHONY: all options clean clobber dist install uninstall test upload_website examples
