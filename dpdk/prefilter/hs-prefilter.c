#include "autoconf.h"
#include "logger.h"
#include "rte_mbuf_core.h"
#include "rte_memzone.h"
#include "util-mpm-hs.h"
#include "util-mpm.h"
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

int CompileHsDbFromShared()
{
    hs_error_t err = HS_SUCCESS;
    err = hs_set_allocator(hs_rte_calloc, rte_free);
    if (err != HS_SUCCESS) {
        Log().error(err, "failed to set HS allocator");
        goto error;
    }

    const struct rte_memzone *memzone =
            rte_memzone_lookup(DPDK_PREFILTER_COMPILE_DATA_MEMZONE_NAME);
    if (memzone == NULL) {
        Log().error(0, "Failed to lookup memzone");
        goto error;
    }

    HSCompileData **compile_data = memzone->addr;

    for (MpmCtxType type = 0; type <= MPM_CTX_TYPE_MAX; type++) {
        HSCompileData *cd = compile_data[type];
        if (cd == NULL)
            continue;
        hs_compile_error_t *compile_err = NULL;

        err = hs_compile_ext_multi((const char *const *)cd->expressions, cd->flags, cd->ids, NULL,
                cd->pattern_cnt, HS_MODE_BLOCK, NULL, &ctx.hs_db_table[type], &compile_err);

        if (err != HS_SUCCESS) {
            Log().error(err, "failed to compile hs db");

            if (compile_err != NULL) {
                Log().error(err, "compilation error: %s", compile_err->message);
                hs_free_compile_error(compile_err);
                goto error;
            }
        }

        if (err != HS_SUCCESS)
            goto error;
    }

    return 0;

error:
    return -1;
}

hs_scratch_t *DevConfHSAllocScratch(struct hs_database *db)
{
    hs_scratch_t *scratch_space = NULL;

    hs_error_t err = hs_alloc_scratch(db, &scratch_space);
    if (err != HS_SUCCESS) {
        SCLogError("Failed to allocate HS scratch space");
        return NULL;
    }

    SCLogInfo("HS scratch space allocated");
    return scratch_space;
}

int MatchEventPrefilter(unsigned int id, unsigned long long from, unsigned long long to,
        unsigned int flags, void *context)
{
    HSCallbackCtx *ctx = context;
    metadata_to_suri_t *metadata_to_suri = ctx->metadata;
    metadata_to_suri->detect_flags |= (1 << ctx->type);

    Log().warning(55, "Matched rule, id %d, from %llu, to %llu", id, from, to);
    SCLogInfo("Matched rule, id %d, from %llu, to %llu", id, from, to);
    return 0;
}

void HSSearch(ring_buffer *packet_buff, hs_scratch_t *scratch_space, MpmCtxType type)
{
    for (int i = 0; i < packet_buff->len; i++) {
        metadata_to_suri_t *metadata_to_suri =
                (metadata_to_suri_t *)rte_mbuf_to_priv(packet_buff->buf[i]);
        metadata_to_suri->detect_flags = PREFILTER_DETECT_FLAG_RAN;
        char *pkt = rte_pktmbuf_mtod(packet_buff->buf[i], char *);
        unsigned int len = packet_buff->buf[i]->pkt_len;

        HSCallbackCtx context = {
            .metadata = metadata_to_suri,
            .type = type,
        };

        /*
        Log().info("scanning");
        for (int i = 0; i < len; i++)
            Log().info("%02x", *(pkt + i));
        */

        hs_scan(ctx.hs_db_table[type], pkt, len, 0, scratch_space, MatchEventPrefilter, &context);

        // Log().info("done");
    }
}

int IPCSetupHS(const struct rte_mp_msg *message, const void *peer)
{
    uint8_t err = 0;
    Log().notice("Called IPCSetupHS");

    err = CompileHsDbFromShared();

    struct rte_mp_msg reply = { 0 };
    strlcpy(reply.name, message->name, sizeof(reply.name));
    reply.param[0] = err;
    reply.len_param = 1;
    rte_mp_reply(&reply, peer);

    Log().notice("Compiled HS databases");

    return 0;
}

#endif // BUILD_HYPERSCAN
