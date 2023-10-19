/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Andrei Shchapaniak <xshcha00@vutbr.cz>
 *
 */

#include "metadata-http.h"
#include "metadata-l3-ipv4.h"
#include "metadata-l3-ipv6.h"
#include "metadata-l4-tcp.h"
#include "metadata-l4-udp.h"
#include "metadata.h"

static inline size_t MetadataGetVlanOffset(struct rte_ether_hdr *eth_hdr, uint16_t *proto)
{
    size_t vlan_offset = 0;
    if (rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) == *proto) {
        struct rte_vlan_hdr *vlan_hdr = (struct rte_vlan_hdr *)(eth_hdr + 1);
        vlan_offset = sizeof(struct rte_vlan_hdr);
        *proto = rte_be_to_cpu_16(vlan_hdr->eth_proto);
        if (rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) == *proto) {
            vlan_hdr = vlan_hdr + 1;
            *proto = vlan_hdr->eth_proto;
            vlan_offset += sizeof(struct rte_vlan_hdr);
        }
    }
    return vlan_offset;
}

int MetadataDecodePacketL4(uint8_t *ptr, metadata_to_suri_t *metadata_to_suri,
        metadata_to_suri_help_t *metadata_to_suri_help, uint8_t proto, size_t len, uint16_t size)
{
    int ret = 0;

    if (proto == IPPROTO_TCP) {
        metadata_to_suri_help->tcp_hdr = (struct rte_tcp_hdr *)(ptr + size);
        ret = MetadataDecodePacketTCP(metadata_to_suri, metadata_to_suri_help, len);
    } else if (proto == IPPROTO_UDP) {
        metadata_to_suri_help->udp_hdr = (struct rte_udp_hdr *)(ptr + size);
        ret = MetadataDecodePacketUDP(metadata_to_suri, metadata_to_suri_help, len);
    }

    return ret;
}

int MetadataDecodePacketL3(struct rte_mbuf *pkt, metadata_to_suri_t *metadata_to_suri,
        metadata_to_suri_help_t *metadata_to_suri_help)
{
    struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type;
    size_t offset;
    int ret = 0;

    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ether_type = eth_hdr->ether_type;
    offset = MetadataGetVlanOffset(eth_hdr,
            &ether_type); // TODO INTERESTING change in if condition translation from cpu to be

    if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        metadata_to_suri_help->ipv4_hdr = (struct rte_ipv4_hdr *)((char *)(eth_hdr + 1) + offset);
        ret = MetadataDecodePacketIPv4(
                metadata_to_suri, metadata_to_suri_help, pkt->pkt_len - ETHERNET_HEADER_LEN);
    } else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
        metadata_to_suri_help->ipv6_hdr = (struct rte_ipv6_hdr *)((char *)(eth_hdr + 1) + offset);
        ret = MetadataDecodePacketIPv6(
                metadata_to_suri, metadata_to_suri_help, pkt->pkt_len - ETHERNET_HEADER_LEN);
    }

    return ret;
}
