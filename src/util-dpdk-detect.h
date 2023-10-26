#ifndef UTIL_DPDK_DETECT_H
#define UTIL_DPDK_DETECT_H

#include "suricata-common.h"
#include <stdint.h>

enum DetectMetadataFlags {
    NO_DETECT_FLAG = BIT_U8(0),
    BRIEF_DETECT_FLAG = BIT_U8(1),
    FULL_DETECT_FLAG = BIT_U8(2),
};

typedef struct MetadataDetectIpv4hdr {
    uint8_t data;
} metadata_detect_ipv4hdr;

typedef struct MetadataDetectHTTP {
    uint8_t data;
} metadata_detect_http;

typedef enum MetadataDPDKDetectType {
    HTTP,
    TCP,
    UDP,
} metadata_dpdk_detect_type_t;

typedef struct MetadataDetect {
    union {
        metadata_detect_ipv4hdr meta_ipv4;
        metadata_detect_http meta_http;
    };
    metadata_dpdk_detect_type_t type;
} metadata_detect_t;

#endif /* UTIL_DPDK_DETECT_H */
