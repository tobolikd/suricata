TOPTARGETS = all clean check
SUBDIRS = prefilter

if BUILD_DPDK

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

install:




.PHONY: $(TOPTARGETS) $(SUBDIRS)

endif