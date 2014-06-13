include config.mk

SRCS := atosl.c subprograms.c common.c
HDRS := atosl.h subprograms.h common.h

TARGET := atosl
TARGET_EXEC := $(TARGET)
TARGET_STATIC_LIB := lib$(TARGET).a
TARGET_SHARED_LIB := lib$(TARGET).so

OBJS := ${SRCS:.c=.o}
DEPS := ${SRCS:.c=.dep}

DIST := ${TARGET}-${VERSION}

.PHONY: all clean distclean dist install uninstall

all:: $(TARGET_STATIC_LIB) $(TARGET_SHARED_LIB) ${TARGET}

${TARGET_STATIC_LIB}: ${OBJS}
	    ${AR} -rcs $@ $^ 

${TARGET_SHARED_LIB}: ${OBJS}
	    ${CC} -o $@ $^ ${LDFLAGS} -shared

${TARGET}: ${OBJS}
	    ${CC} -o $@ $^ ${LDFLAGS}

${OBJS}: %.o: %.c %.dep ${HDRS} config.mk $(wildcard config.mk.local)
	    ${CC} ${CFLAGS} -o $@ -c $<

${DEPS}: %.dep: %.c Makefile
	    ${CC} ${CFLAGS} -MM $< > $@

clean:
	    -rm -f *~ *.o *.a *.so *.dep ${TARGET} ${DIST}.tar.gz

dist: clean
	mkdir -p ${DIST}
	cp -R LICENSE PATENTS Makefile README.md config.mk ${SRCS} ${HDRS} ${DIST}
	tar -cf ${DIST}.tar ${DIST}
	gzip ${DIST}.tar
	rm -rf ${DIST}

install: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	mkdir -p ${DESTDIR}${PREFIX}/lib
	mkdir -p ${DESTDIR}${PREFIX}/include
	cp -f atosl ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/atosl
	cp -f libatosl.* ${DESTDIR}${PREFIX}/lib
	cp -f atosl.h ${DESTDIR}${PREFIX}/include

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/atosl

distclean:: clean
