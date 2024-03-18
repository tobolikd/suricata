#ifndef HS_PREFILTER_H
#define HS_PREFILTER_H

#include "autoconf.h"
#include "lcore-worker.h"
#include "rte_eal.h"

#ifdef BUILD_HYPERSCAN

#include <hs/hs_runtime.h>
#include "util-dpdk.h"

/* compile hs db
 */
int DevConfHSInit();

/* allocates scratch space
 *
 * scratch space is allocated per thread,
 * allocattion required pattern database as the size of scratch space depends on it
 */
hs_scratch_t *DevConfHSAllocScratch();

void HSSearch(ring_buffer *packet_buff, hs_scratch_t *scratch_space);

int IPCSetupHS(const struct rte_mp_msg *message, const void *peer);
int IPCAllocSharedMemory(const struct rte_mp_msg *message, const void *peer);

#endif // BUILD_HYPERSCAN

#endif // HS_PREFILTER_H
