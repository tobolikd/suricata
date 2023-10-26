#ifndef PREFILTER_UTIL_MPM_HS_H
#define PREFILTER_UTIL_MPM_HS_H

#include <stdint.h>

void MpmHSRegisterPrefilter(void);

typedef struct PrefilterHSMatches {
    uint32_t *signature_ids;
    uint32_t sinature_size;

} pref_hs_matches_t;

extern pref_hs_matches_t prefilter_hs_matches;

#endif // PREFILTER_UTIL_MPM_HS_H
