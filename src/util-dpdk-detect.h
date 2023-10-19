#ifndef UTIL_DPDK_DETECT_H
#define UTIL_DPDK_DETECT_H

#include <stdint.h>

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
