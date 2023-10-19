#include "metadata-http.h"
#include "util-dpdk.h"

int MetadataDetectPacketHTTP(struct rte_mbuf *pkt, metadata_to_suri_t *metadata)
{
    int ret = 0;

    metadata->metadata_detect.meta_http.data = 1;

    return ret;
}
