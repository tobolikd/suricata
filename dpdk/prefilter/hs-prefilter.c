#include "autoconf.h"
#include "lcore-worker.h"
#include "lcores-manager.h"
#include "logger.h"
#include "rte_mbuf_core.h"
#include "rte_memzone.h"
#include "util-mpm-hs.h"
#include <pthread.h>
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

// scratch space to reuse
static hs_scratch_t *scratch_space = NULL;
static pthread_mutex_t scratch_space_mutex = PTHREAD_MUTEX_INITIALIZER;

int ThreadSuricataAllocScratch(struct lcore_values *lv)
{
    hs_error_t err = HS_SUCCESS;

    pthread_mutex_lock(&scratch_space_mutex);
    if (scratch_space == NULL) {
        // if not created, allocate scratch space
        for (MpmCtxType type = 0; type <= MPM_CTX_TYPE_MAX; type++) {
            hs_database_t *db = ctx.hs_db_table[type];
            if (db == NULL)
                continue;

            err = hs_alloc_scratch(db, &scratch_space);
            if (err || scratch_space == NULL) {
                pthread_mutex_unlock(&scratch_space_mutex);
                goto error;
            }
        }

        lv->hs_scratch_space = scratch_space;
        pthread_mutex_unlock(&scratch_space_mutex);
    } else {
        pthread_mutex_unlock(&scratch_space_mutex);
        err = hs_clone_scratch(scratch_space, &lv->hs_scratch_space);
        if (err || lv->hs_scratch_space == NULL)
            goto error;
    }

    return 0;
error:
    Log().error(err, "failed to allocate scratch space");
    return -1;
}

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
    /* when enabled memory allocation collides with mp_malloc_sync and sending
     * ip message to main app fails
    err = hs_set_allocator(hs_rte_calloc, rte_free);
    if (err != HS_SUCCESS) {
        Log().error(err, "failed to set HS allocator");
        goto error;
    }
    */

    const struct rte_memzone *memzone =
            rte_memzone_lookup(DPDK_PREFILTER_COMPILE_DATA_MEMZONE_NAME);
    if (memzone == NULL) {
        Log().error(0, "Failed to lookup memzone");
        goto error;
    }

    HSCompileData **compile_data_arr = memzone->addr;

    for (MpmCtxType type = 0; type <= MPM_CTX_TYPE_MAX; type++) {
        HSCompileData *cd = compile_data_arr[type];
        if (cd == NULL)
            continue;

        hs_compile_error_t *compile_err = NULL;
        err = hs_compile_ext_multi((const char *const *)cd->expressions, cd->flags, cd->ids, NULL,
                cd->pattern_cnt, HS_MODE_BLOCK, NULL, &ctx.hs_db_table[type], &compile_err);

        if (err != HS_SUCCESS) {
            if (compile_err != NULL) {
                Log().error(err, "compilation error: %s", compile_err->message);
                hs_free_compile_error(compile_err);
            }
            goto error;
        }
    }

    return 0;

error:
    return -1;
}

int MatchEventPrefilter(unsigned int id, unsigned long long from, unsigned long long to,
        unsigned int flags, void *context)
{
    HSCallbackCtx *ctx = context;
    metadata_to_suri_t *metadata_to_suri = ctx->metadata;
    metadata_to_suri->detect_flags |= (1 << ctx->type);

    Log().warning(0, "Matched rule, id %d, from %llu, to %llu", id, from, to);
    return 0;
}

void HSSearch(ring_buffer *packet_buff, hs_scratch_t *scratch_space, MpmCtxType type)
{
    for (int i = 0; i < packet_buff->len; i++) {
        metadata_to_suri_t *metadata_to_suri =
                (metadata_to_suri_t *)rte_mbuf_to_priv(packet_buff->buf[i]);
        metadata_to_suri->detect_flags |= PREFILTER_DETECT_FLAG_RAN;
        char *pkt = rte_pktmbuf_mtod(packet_buff->buf[i], char *);
        unsigned int len = packet_buff->buf[i]->pkt_len;

        HSCallbackCtx context = {
            .metadata = metadata_to_suri,
            .type = type,
        };

        Log().info("scanning");
        /*
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

    /*
    err = CompileHsDbFromShared();
    if (err) {
        Log().error(err, "Failed to compile hs db");
        goto finish;
    }
    */

    uint16_t timeout_sec = 5;
    err = LcoreStateCheckAllWTimeout(LCORE_OFFLOADS_DONE, timeout_sec);
    if (err) {
        Log().error(err, "Workers haven't finished offloads setup");
        goto finish;
    }

    if (ctx.lcores_state.lcores_arr_len < 1) {
        Log().error(err, "Lcores array not initialized");
        err = -1;
        goto finish;
    }

    // assign first thread to init the hs db
    rte_atomic16_t **state = &ctx.lcores_state.lcores_arr[0].state;
    LcoreStateSet(*state, LCORE_HS_DB_INIT);
    timeout_sec = 300;
    LcoreStateWaitWithTimeout(*state, LCORE_HS_DB_DONE, timeout_sec);

    for (uint16_t i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
        LcoreStateSet(ctx.lcores_state.lcores_arr[i].state, LCORE_SCRATCH_INIT);
    }

    timeout_sec = 10;
    err = LcoreStateCheckAllWTimeout(LCORE_SCRATCH_DONE, timeout_sec);
    if (err) {
        Log().error(err, "Scratch space init not done in %s sec", timeout_sec);
        goto finish;
    }

    Log().notice("Compiled HS databases");

finish:

    struct rte_mp_msg reply = { 0 };
    strlcpy(reply.name, message->name, sizeof(reply.name));
    reply.param[0] = err;
    reply.len_param = 1;
    rte_mp_reply(&reply, peer);

    return err;
}

#endif // BUILD_HYPERSCAN
