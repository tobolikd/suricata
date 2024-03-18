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

#ifndef LCORES_MANAGER_H
#define LCORES_MANAGER_H

#include <rte_atomic.h>

#include "dev-conf.h"
#include "stats.h"
#include "hash-table-bypass.h"

struct lcore_init {
    struct ring_list_entry *re;
    uint16_t ring_offset_start;
    uint16_t rings_cnt;
    uint16_t lcore_id;
    struct pf_stats *stats;
    rte_atomic16_t *state;
    struct rte_table_hash *bypass_table;
};

enum LcoreStateEnum {
    LCORE_WAIT, // default state
    /* "commands" */
    LCORE_INIT,
    LCORE_RUN,
    LCORE_STOP,
    LCORE_STAT_DUMP,
    LCORE_DETACH,
    LCORE_HALT,
    /* "replies" */
    LCORE_INIT_DONE,
    LCORE_RUNNING,
    LCORE_RUNNING_DONE,
    LCORE_STAT_DUMP_DONE,
    LCORE_STOP_DONE,
    LCORE_OFFLOADS_INIT,
    LCORE_OFFLOADS_DONE,
    LCORE_RULES_INIT,
    LCORE_RULES_DONE,
};

extern struct lcore_init *LcoreMainAsWorker;

int LcoreManagerRunWorkers(struct pf_stats *stats);
rte_atomic16_t *LcoreStateInit(void);
void LcoreStateSet(rte_atomic16_t *state, enum LcoreStateEnum new_state);
int LcoreStateCheck(rte_atomic16_t *state, enum LcoreStateEnum check_state);
int LcoreStateWaitWithTimeout(
        rte_atomic16_t *state, enum LcoreStateEnum check_state, uint16_t timeout_sec);
bool LcoreStateCheckAll(enum LcoreStateEnum check_state);
int LcoreStateCheckAllWTimeout(enum LcoreStateEnum check_state, uint16_t timeout_sec);
uint32_t LcoreManagerGetLcoreIdFromRingId(
        uint16_t ring_id, uint16_t sec_app_lcores_cnt, uint16_t pf_lcores_cnt);

int LcoreStateCheckAllByRingTimeout(
        enum LcoreStateEnum check_state, char *iface, uint16_t timeout_sec);
bool LcoreStateCheckAllByRing(enum LcoreStateEnum check_state, char *iface);

#endif // LCORES_MANAGER_H
