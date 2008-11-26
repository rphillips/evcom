include config.mk

DEP = oi.h
SRC = oi.c
OBJ = ${SRC:.c=.o}

VERSION = 0.1
NAME=liboi
OUTPUT_LIB=$(NAME).$(SUFFIX).$(VERSION)
OUTPUT_A=$(NAME).a

LINKER=$(CC) $(LDOPT)

all: options $(OUTPUT_LIB) $(OUTPUT_A) test/ping_pong

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

FAIL=echo "\033[1;31mFAIL\033[m"
PASS=echo "\033[1;32mPASS\033[m"
TEST= && $(PASS) || $(FAIL)

test: test/ping_pong
	@echo "ping pong"
	@echo -n "- unix: "
	@./test/ping_pong unix $(TEST)
	@echo -n "- tcp: "
	@./test/ping_pong tcp $(TEST)
	@echo -n "- unix secure: "
	@./test/ping_pong unix secure $(TEST)
	@echo -n "- tcp secure: "
	@./test/ping_pong tcp secure $(TEST)

test/ping_pong: test/ping_pong.c $(OUTPUT_A)
	@echo BUILDING test/ping_pong
	$(CC) -I. $(LIBS) $(CFLAGS) -lev -o $@ $^

clean:
	@echo CLEANING
	@rm -f ${OBJ} $(OUTPUT_A) $(OUTPUT_LIB) $(NAME)-${VERSION}.tar.gz 
	@rm -f test/ping_pong  
	@rm -f examples/echo  

clobber: clean
	@echo CLOBBERING

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

.PHONY: all options clean clobber install uninstall test 
