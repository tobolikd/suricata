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

#include <stdio.h>
#include <malloc.h>
#include <errno.h>

#include "logger.h"
#include "dev-conf.h"

struct DeviceConfigurer devconf;
ring_tailq_t tailq_ring_head = TAILQ_HEAD_INITIALIZER(tailq_ring_head);

void RingListInitHead(void)
{
    TAILQ_INIT(&tailq_ring_head);
}

int RingListAddConf(void *ring_conf)
{
    struct ring_entry *ring_entry = calloc(sizeof(struct ring_entry), 1);
    if (ring_entry == NULL) {
        Log().error(ENOMEM, "No memory for ring entry\n");
        return -ENOMEM;
    }

    ring_entry->ring_conf = ring_conf;
    TAILQ_INSERT_TAIL(&tailq_ring_head, ring_entry, entries);
    return 0;
}


void DevConfInit(struct DeviceConfigurer ops)
{
    devconf = ops;
}

int DevConfConfigureBy(void *conf)
{
    return devconf.ConfigureBy(conf);
}

