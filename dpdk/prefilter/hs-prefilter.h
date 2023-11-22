#ifndef HS_PREFILTER_H
#define HS_PREFILTER_H

#include "autoconf.h"

#ifdef BUILD_HYPERSCAN

#include <hs/hs_runtime.h>

/* compile hs db
 */
int DevConfHSInit();

/* allocates scratch space
 *
 * scratch space is allocated per thread,
 * allocattion required pattern database as the size of scratch space depends on it
 */
hs_scratch_t* DevConfHSAllocScratch();

#endif // BUILD_HYPERSCAN

#endif // HS_PREFILTER_H
