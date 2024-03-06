#include "autoconf.h"
#include "logger.h"
#include "rte_mbuf_core.h"
#include "util-mpm-hs.h"
#include "util-mpm.h"
#include <stdint.h>
#include <stdlib.h>
#ifdef BUILD_HYPERSCAN
#include <hs/hs_common.h>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>
#include <stddef.h>
#include <sys/types.h>

#include "hs-prefilter.h"
#include "prefilter.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "rte_malloc.h"

/**
 * wrapper for hyperscan malloc
 */
void *hs_rte_calloc(size_t size)
{
    return rte_calloc("hyperscan allocations", 1, size, 0);
}

int DevConfHSInit()
{
    hs_error_t err = HS_SUCCESS;
    err = hs_set_allocator(hs_rte_calloc, rte_free);
    if (err != HS_SUCCESS) {
        Log().error(err, "failed to set HS allocator");
        goto error;
    }

    /**
    // TMP*
    // change to geting it from config/suri
    const char *const *expressions = (const char *const[]){ "test" };
    const unsigned int flags = HS_FLAG_PREFILTER | HS_FLAG_CASELESS;
    const unsigned int *match_ids =
            (const unsigned int[]){ 5555 }; // TODO* array of ids for each rule
    unsigned int element_count = 1;         // TODO* count elements
    */
    // TODO* get shared compile data
    HSCompileData *compile_data = NULL; // InitCompileDataFromSuriMPMCtx(NULL);

    // add prefilter flag for each pattern
    for (uint32_t i = 0; i < compile_data->pattern_cnt; i++) {
        compile_data->flags[i] |= HS_FLAG_PREFILTER;
    }

    hs_compile_error_t *compile_err = NULL;

    err = hs_compile_ext_multi((const char *const *)compile_data->expressions, compile_data->flags,
            compile_data->ids, NULL, compile_data->pattern_cnt, HS_MODE_BLOCK, NULL,
            &ctx.hs_database, &compile_err);

    if (err != HS_SUCCESS) {
        Log().error(err, "failed to compile hs db");

        if (compile_err != NULL) {
            Log().error(err, "compilation error: %s", compile_err->message);
            hs_free_compile_error(compile_err);
            goto error;
        }
    }

    return 0;

error:
    return -1;
}

hs_scratch_t *DevConfHSAllocScratch()
{
    hs_scratch_t *scratch_space = NULL;

    if (ctx.hs_database == NULL) {
        SCLogError("Hyperscan db not created");
        goto error;
    }

    // TODO* use hs_clone_scratch instead
    hs_error_t err = hs_alloc_scratch(ctx.hs_database, &scratch_space);
    if (err) {
        SCLogError("Failed to allocate HS scratch space");
        goto error;
    }

    SCLogInfo("HS scratch space allocated");
    return scratch_space;

error:
    return NULL;
}

int MatchEventPrefilter(unsigned int id, unsigned long long from, unsigned long long to,
        unsigned int flags, void *context)
{
    metadata_to_suri_t *metadata_to_suri = (metadata_to_suri_t *)context;
    metadata_to_suri->detect_flags |= PREFILTER_DETECT_FLAG_MATCH;

    Log().warning(55, "Matched rule, id %d, from %llu, to %llu", id, from, to);
    SCLogInfo("Matched rule, id %d, from %llu, to %llu", id, from, to);
    return 0;
}

void HSSearch(ring_buffer *packet_buff, hs_scratch_t *scratch_space)
{
    for (int i = 0; i < packet_buff->len; i++) {
        metadata_to_suri_t *metadata_to_suri =
                (metadata_to_suri_t *)rte_mbuf_to_priv(packet_buff->buf[i]);
        metadata_to_suri->detect_flags = PREFILTER_DETECT_FLAG_RAN;
        char *pkt = rte_pktmbuf_mtod(packet_buff->buf[i], char *);
        unsigned int len = packet_buff->buf[i]->pkt_len;
        Log().info("scanning");
        for (int i = 0; i < len; i++)
            Log().info("%02x", *(pkt + i));
        Log().info("done");
        hs_scan(ctx.hs_database, pkt, len, 0, scratch_space, MatchEventPrefilter,
                &metadata_to_suri);
    }
}

#endif // BUILD_HYPERSCAN
