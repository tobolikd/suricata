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
 * \author Lukas Sismis <lukas.sismis@cesnet.cz>
 */

#include "lcore-worker-suricata.h"
#include "lcores-manager.h"
#include "lcore-worker.h"
#include "dev-conf.h"
#include "dev-conf-suricata.h"
#include "logger.h"
#include "util-prefilter.h"

#include <rte_ethdev.h>
#include <rte_malloc.h>

#define PKT_ORIGIN_PORT1 PKT_FIRST_FREE
//#undef PKT_FIRST_FREE
//#define PKT_FIRST_FREE PKT_ORIGIN_PORT1 << 1

struct lcore_values *ThreadSuricataInit(struct lcore_init *init_vals)
{
    int ret;
    struct ring_list_entry *re = (struct ring_list_entry *)init_vals->re;
    struct ring_list_entry_suricata *suri_entry =
            (struct ring_list_entry_suricata *)re->pre_ring_conf;

    struct lcore_values *lv = rte_calloc("struct lcore_values", 1, sizeof(struct lcore_values), 0);
    if (lv == NULL) {
        Log().error(EINVAL, "Error (%s): memory allocation error of lcore_values for ring %s lcoreid %u", rte_strerror(rte_errno), re->main_ring.name_base, rte_lcore_id());
        return NULL;
    }

    lv->port1_addr = suri_entry->nic_conf.port1_pcie;
    ret = rte_eth_dev_get_port_by_name(lv->port1_addr, &lv->port1_id);
    if (ret != 0) {
        Log().error(EINVAL, "Error (%s): Unable to obtain port qid of %s", rte_strerror(-ret), lv->port1_addr);
        return NULL;
    }

    lv->port2_addr = suri_entry->nic_conf.port2_pcie;
    ret = rte_eth_dev_get_port_by_name(lv->port2_addr, &lv->port2_id);
    if (ret != 0) {
        Log().error(EINVAL, "Error (%s): Unable to obtain port qid of %s", rte_strerror(-ret), lv->port2_addr);
        return NULL;
    }

    lv->socket_id = rte_socket_id();
    lv->qid = init_vals->lcore_id;
    lv->opmode = re->opmode;
    lv->ring_offset_start = init_vals->ring_offset_start;
    lv->rings_cnt = init_vals->rings_cnt;

    lv->rings_from_pf = rte_calloc("struct rte_ring *", lv->rings_cnt, sizeof(struct rte_ring *), 0);
    lv->rings_to_pf = rte_calloc("struct rte_ring *", lv->rings_cnt, sizeof(struct rte_ring *), 0);

    // find rings
    for (uint16_t i = 0; i < init_vals->rings_cnt; i++) {
        uint16_t ring_id = lv->ring_offset_start + i;
        struct rte_ring *r;
        const char *name = DevConfRingGetRxName(re->main_ring.name_base, ring_id);
        r = rte_ring_lookup(name);
        if (r == NULL) {
            Log().error(EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno), name);
            return NULL;
        }

        lv->rings_from_pf[i] = r;

        if (re->opmode != IDS) {
            name = DevConfRingGetTxName(re->main_ring.name_base, ring_id);
            r = rte_ring_lookup(name);
            if (r == NULL) {
                Log().error(EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno), name);
                return NULL;
            }

            lv->rings_to_pf[i] = r;
        }
    }

    // allocate pkt ring buffer
    lv->rb = rte_calloc("ring_buffer", sizeof(ring_buffer), init_vals->rings_cnt, 0);
    if (lv->rb == NULL) {
        Log().error(EINVAL, "Error (%s): Unable to allocate memory for ring queues of ring %s lcoreid %u", rte_strerror(-ret), re->main_ring.name_base, lv->qid);
        return NULL;
    }

    return lv;
}

void ThreadSuricataRun(struct lcore_values *lv)
{
    uint32_t pkt_count = 0, pkt_count1 = 0, pkt_count2 = 0;
    uint16_t queue_id;
    struct rte_mbuf *pkts[2 * BURST_SIZE] = { NULL };
    struct rte_mbuf *pkts_nic2[2 * BURST_SIZE] = { NULL };
    memset(&lv->stats, 0, sizeof(lv->stats)); // null the stats

    Log().notice("Lcore %u trying to rcv from %s (p%d)", lv->qid, lv->port1_addr, lv->port1_id);
    if (lv->opmode != IDS)
        Log().notice("Lcore %u trying to rcv from %s (p%d)", lv->qid, lv->port2_addr, lv->port2_id);

    if (lv->qid == 0) {
        rte_eth_dev_start(lv->port1_id);
        if (lv->opmode != IDS)
            rte_eth_dev_start(lv->port2_id);
    }

    while (!ShouldStop()) {
        pkt_count1 = rte_eth_rx_burst(lv->port1_id, lv->qid, pkts, BURST_SIZE);

        if (lv->opmode != IDS) {
            pkt_count2 = rte_eth_rx_burst(lv->port2_id, lv->qid, pkts + pkt_count1, BURST_SIZE);
        }
        lv->stats.pkts_rx += pkt_count1 + pkt_count2;

        for (uint32_t i = 0; i < pkt_count1; i++) {
            queue_id = pkts[i]->hash.rss % lv->rings_cnt;
            lv->rb[queue_id].buf[lv->rb[queue_id].len] = pkts[i];
            lv->rb[queue_id].buf[lv->rb[queue_id].len]->ol_flags |= PKT_ORIGIN_PORT1;
            lv->rb[queue_id].len++;
        }

        for (uint32_t i = pkt_count1; i < pkt_count1 + pkt_count2; i++) {
            queue_id = pkts[i]->hash.rss % lv->rings_cnt;
            lv->rb[queue_id].buf[lv->rb[queue_id].len] = pkts[i];
            lv->rb[queue_id].buf[lv->rb[queue_id].len]->ol_flags &= ~PKT_ORIGIN_PORT1;
            lv->rb[queue_id].len++;
        }

        for (uint16_t i = 0; i < lv->rings_cnt; i++) {
            pkt_count = rte_ring_enqueue_burst(lv->rings_from_pf[i], (void **)lv->rb[i].buf, lv->rb[i].len, NULL);
            lv->stats.pkts_enq += pkt_count;
            if (pkt_count > 0) {
                Log().debug("ENQ %d packet/s to rxring %s", pkt_count, lv->rings_from_pf[i]->name);
            }

            // this could have been aggregated first to one array and then freed
            if (pkt_count < lv->rb[i].len) {
                rte_pktmbuf_free_bulk(lv->rb[i].buf + pkt_count, lv->rb[i].len - pkt_count);
            }

            lv->rb[i].len = 0;
        }

        if (lv->opmode != IDS) {
            // deq
            for (uint16_t ring_id = 0; ring_id < lv->rings_cnt; ring_id++) {
                pkt_count = rte_ring_dequeue_burst(lv->rings_to_pf[ring_id], (void **)lv->rb[ring_id].buf, BURST_SIZE * 2, NULL);
                lv->stats.pkts_deq += pkt_count;
                if (pkt_count > 0) {
                    Log().debug("DEQ %d packet/s from txring %s\n", pkt_count, lv->rings_to_pf[ring_id]->name);
                }
                lv->rb[ring_id].len = pkt_count;
                pkt_count1 = 0;
                pkt_count2 = 0;
                for (uint16_t i = 0; i < lv->rb[ring_id].len; i++) {
                    if (lv->rb[ring_id].buf[i]->ol_flags & PKT_ORIGIN_PORT1)
                        pkts[pkt_count1++] = lv->rb[ring_id].buf[i];
                    else
                        pkts_nic2[pkt_count2++] = lv->rb[ring_id].buf[i];
                }
                lv->rb[ring_id].len = 0;
            }

            // tx to ports
            pkt_count = rte_eth_tx_burst(lv->port1_id, lv->qid, pkts, pkt_count1);
            lv->stats.pkts_tx += pkt_count;
            if (pkt_count < pkt_count1) {
                rte_pktmbuf_free_bulk(pkts + pkt_count, pkt_count1 - pkt_count);
            }

            pkt_count = rte_eth_tx_burst(lv->port2_id, lv->qid, pkts_nic2, pkt_count2);
            lv->stats.pkts_tx += pkt_count;
            if (pkt_count < pkt_count2) {
                rte_pktmbuf_free_bulk(pkts_nic2 + pkt_count, pkt_count2 - pkt_count);
            }
        }
    }
}

void ThreadSuricataDeinit(struct lcore_init *vals, struct lcore_values *lv) {
    int ret;
    if (vals != NULL)
        rte_free(vals);
    if (lv != NULL) {
        if (lv->qid == 0) {
            ret = rte_eth_dev_stop(lv->port1_id);
            if (ret != 0)
                Log().error(-ret, "Error (%s): unable to stop device %s", rte_strerror(-ret), lv->port1_addr);

            if (lv->opmode != IDS) {
                rte_eth_dev_stop(lv->port2_id);
                if (ret != 0)
                    Log().error(-ret, "Error (%s): unable to stop device %s", rte_strerror(-ret), lv->port2_addr);
            }
        }

        rte_free(lv);
    }
}