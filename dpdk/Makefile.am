TOPTARGETS = shared static check
SUBDIRS = prefilter

if BUILD_DPDK_APPS

help:
	echo "install Suricata, Suricata headers and library and run make dpdk-apps from root"
	exit 1

$(TOPTARGETS): $(SUBDIRS)

clean: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

install:




.PHONY: $(TOPTARGETS) $(SUBDIRS) install install-deps

endif