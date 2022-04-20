# EXTRA_DIST = prefilter.c util-prefilter.c logger.c logger-basic.c dev-conf.c dev-conf-suricata.c lcores-manager.c \
    lcore-worker.c lcore-worker-suricata.c stats.c \
    prefilter.h util-prefilter.h logger.h logger-basic.h dev-conf.h dev-conf-suricata.h lcores-manager.h \
    lcore-worker.h lcore-worker-suricata.h stats.h

if BUILD_DPDK_APPS

# binary name
APP = prefilter

# all source are stored in SRCS
SRCS = \
    prefilter.c \
    util-prefilter.c \
    logger.c \
    logger-basic.c \
    dev-conf.c \
    dev-conf-suricata.c \
    lcores-manager.c \
    lcore-worker.c \
    lcore-worker-suricata.c \
    stats.c

OBJS = \
    prefilter.o \
    util-prefilter.o \
    logger.o \
    logger-basic.o \
    dev-conf.o \
    dev-conf-suricata.o \
    lcores-manager.o \
    lcore-worker.o \
    lcore-worker-suricata.o \
    stats.o

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF ?= pkg-config

PC_FILE = $(LIBDPDK_PC_FILE)
CFLAGS += -O3 $(LIBDPDK_CFLAGS) -I $(CONFIGURE_PREFIX)/include/suricata/ -I $(CONFIGURE_PREFIX)/include/ -DHAVE_DPDK -DTLS_C11
LDFLAGS_SHARED = $(LIBDPDK_LDFLAGS_SHARED) -L $(CONFIGURE_PREFIX)/lib/ -lsuricata -lhtp $(LIBS)
LDFLAGS_STATIC = $(LIBDPDK_LDFLAGS_STATIC)

CFLAGS += -I. -DALLOW_EXPERIMENTAL_API

$(OBJS): %.o: %.c Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) -c $< -o $@

build/$(APP)-shared: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

install-deps:
	$(MAKE) -C ../../ install
	$(MAKE) -C ../../ install-headers
	$(MAKE) -C ../../ install-library


build: install-deps
if !BUILD_DPDK_APPS
	echo "no installation of DPDK found"
	exit 1
endif
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)* build/*.o
	rm -f $(APP){,-shared,-static} *.o
	test -d build && rmdir -p build || true

endif