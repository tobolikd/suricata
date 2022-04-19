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

# Build using pkg-config variables if possible
if !BUILD_DPDK
$(error "no installation of DPDK found")
endif

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF ?= pkg-config

PC_FILE = $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk) -I $(CONFIGURE_PREFIX)/include/suricata/ -I $(CONFIGURE_PREFIX)/include/ -DHAVE_DPDK -DTLS_C11
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -L $(CONFIGURE_PREFIX)/lib/ -lsuricata -lhtp $(LIBS)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

CFLAGS += -I. -DALLOW_EXPERIMENTAL_API

OBJS = $(patsubst %.c,build/%.o,$(SRCS))

build/%.o: %.c Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) -c $< -o $@

build/$(APP)-shared: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)* build/*.o
	test -d build && rmdir -p build || true
