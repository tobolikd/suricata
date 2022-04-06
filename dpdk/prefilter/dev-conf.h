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

#ifndef DEV_CONF_H
#define DEV_CONF_H

#include <sys/queue.h>

typedef int (*start_ring)(void *ring_conf);
typedef int (*fill_ring)(void *ring_conf);
typedef int (*stop_ring)(void *ring_conf);

struct ring_list_entry {
    // here I would like to have config separately for RX rings, bypass table, task ring...
    // or at least already created instances of things / API functions
    // e.g. (rte_ring *, bypass_table_lookup(), bypass_table...)
    void *pre_ring_conf; // here should be stored either raw config or everything not covered before
    start_ring start;
//    fill_ring fill;
    stop_ring stop;
    TAILQ_ENTRY(ring_list_entry) entries;
    TAILQ_HEAD(, ring_list_entry) head;
};

typedef TAILQ_HEAD(ring_tailq_head, ring_list_entry) ring_tailq_t;
extern ring_tailq_t tailq_ring_head;

typedef int (*configure_by)(void *conf);

struct DeviceConfigurer {
    configure_by ConfigureBy;
};

void DevConfInit(struct DeviceConfigurer ops);
int DevConfConfigureBy(void *conf);

void RingListInitHead(void);
int RingListAddConf(const struct ring_list_entry *re);

#endif // DEV_CONF_H
