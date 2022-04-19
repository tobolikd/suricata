TOPTARGETS = all clean check
DPDK_SUBDIRS = prefilter

if BUILD_DPDK

$(TOPTARGETS): $(DPDK_SUBDIRS)
$(DPDK_SUBDIRS):
	$(MAKE) -C $@

install:


.PHONY: $(TOPTARGETS) $(DPDK_SUBDIRS)

endif