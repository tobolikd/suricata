#ifndef HS_PREFILTER_H
#define HS_PREFILTER_H

#include "autoconf.h"
#include "lcore-worker.h"
#include "rte_eal.h"
#include "util-dpdk.h"

#ifdef BUILD_HYPERSCAN
#include <hs/hs_common.h>
#include <hs/hs_runtime.h>

typedef struct HSCallbackCtx_ {
    MpmCtxType type;
    metadata_to_suri_t *metadata;
} HSCallbackCtx;

int ThreadSuricataAllocScratch(struct lcore_values *lv);

/* compile hs db
 */
int CompileHsDbFromShared();

void HSSearch(ring_buffer *packet_buff, hs_scratch_t *scratch_space, MpmCtxType type);

int IPCSetupHS(const struct rte_mp_msg *message, const void *peer);

#endif // BUILD_HYPERSCAN

#endif // HS_PREFILTER_H
