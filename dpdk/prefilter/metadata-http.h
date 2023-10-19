#ifndef PREFILTER_METADATA_HTTP
#define PREFILTER_METADATA_HTTP

#include "rte_mbuf_core.h"
#include "util-dpdk.h"

int MetadataDetectPacketHTTP(struct rte_mbuf *pkt, metadata_to_suri_t *metadata);

#endif // PREFILTER_METADATA_HTTP
