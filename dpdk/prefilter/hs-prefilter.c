#include "autoconf.h"
#ifdef BUILD_HYPERSCAN

#include <hs/hs_common.h>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>
#include <stddef.h>

#include "hs-prefilter.h"
#include "prefilter.h"
#include "util-debug.h"
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
    hs_set_allocator(hs_rte_calloc, rte_free);

    // TMP*
    // change to geting it from config/suri
    const char *const *expressions;
    const unsigned int flags = HS_FLAG_PREFILTER; // TODO* add flags
    unsigned int match_ids;                       // TODO* array of ids for each rule
    unsigned int element_count = 1;               // TODO* count elements

    hs_compile_error_t *compile_err = NULL;
    hs_error_t err = HS_SUCCESS;

    err = hs_compile_ext_multi(expressions, &flags, &match_ids, NULL, element_count, HS_MODE_BLOCK,
            NULL, &ctx.hs_database, &compile_err);

    if (err != HS_SUCCESS) {
        SCLogError("failed to compile hyperscan database");

        if (compile_err != NULL) {
            SCLogError("compilation error: %s", compile_err->message);
            hs_free_compile_error(compile_err);
            goto error;
        }
    }

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

    hs_error_t err = hs_alloc_scratch(ctx.hs_database, &scratch_space);

error:
    return NULL;
}

#endif // BUILD_HYPERSCAN
