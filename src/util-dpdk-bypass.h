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
 * \author Lukas Sismis <sismis@cesnet.cz>
 */

#ifndef UTIL_DPDK_PREFILTER_H
#define UTIL_DPDK_PREFILTER_H

#include "suricata.h"
#include "util-dpdk.h"
#include "flow-bypass.h"

extern int32_t ipc_app_id;

void DpdkIpcRegisterActions(void);

void DpdkIpcStart(void);
void DpdkIpcStop(void);
void DpdkIpcDumpStats(void);
void DpdkIpcDetach(void);

#ifdef HAVE_DPDK
#define IPC_VALID_RESPONSE "ok"

#define IPC_ACTION_ATTACH                "attach"
#define IPC_ACTION_DETACH                "detach"
#define IPC_ACTION_START                 "pkts_start"
#define IPC_ACTION_STOP                  "pkts_stop"
#define IPC_ACTION_SHUTDOWN              "shutdown"
#define IPC_ACTION_BYPASS_TBL_DUMP_START "bt_dump_start"
#define IPC_ACTION_BYPASS_TBL_DUMP_STOP  "bt_dump_stop"
#define IPC_ACTION_OFFLOADS_SETUP        "offloads_setup"
#define IPC_ACTION_HYPERSCAN_SETUP       "hyperscan_setup"

struct IPCResponseAttach {
    uint32_t app_id;
    char memzone_name[RTE_MEMZONE_NAMESIZE];
};

struct PFMessage {
    enum PFMessageType msg_type;
    int use_cnt;
    FlowKey fk;
    struct PFMessage *next_msg;
    union {
        struct {
            // TODO: add some generic space for vendor stuff (e.g. mbuf rss)
        } bypass_add_msg;
        struct {
        } bypass_delete_msg;
        struct {
        } bypass_err_flow_not_found_msg;
        struct {
            uint64_t tosrcpktcnt;
            uint64_t tosrcbytecnt;
            uint64_t todstpktcnt;
            uint64_t todstbytecnt;
        } bypass_evict_msg;
        struct {
            uint64_t tosrcpktcnt;
            uint64_t tosrcbytecnt;
            uint64_t todstpktcnt;
            uint64_t todstbytecnt;
        } bypass_force_evict_msg;
        struct {
            uint64_t tosrcpktcnt;
            uint64_t tosrcbytecnt;
            uint64_t todstpktcnt;
            uint64_t todstbytecnt;
        } update_msg;
    };
};

enum FlowDirectionEnum { TO_SRC, TO_DST };

struct FlowKeyDirection {
    uint8_t src_addr : 1;
    uint8_t src_port : 1;
    uint8_t spare : 6;
};

typedef struct FlowKeyExtended {
    FlowKey *fk;
    struct FlowKeyDirection *fd;
} FlowKeyExtended;

void PFMessageAddBypassInit(struct PFMessage *msg);
void PFMessageDeleteBypassInit(struct PFMessage *msg);
void PFMessageHardDeleteBypassInit(struct PFMessage *msg);
void PFMessageForceEvictBypassInit(struct PFMessage *msg);
void PFMessageEvictBypassInit(struct PFMessage *msg);
void PFMessageErrorFlowNotFoundBypassInit(struct PFMessage *msg);

int FlowKeyInitFromFlow(FlowKey *fk, Flow *f);

struct FlowKeyDirection FlowKeyUnify(FlowKey *fk);
void FlowKeyReconstruct(FlowKey *fk, struct FlowKeyDirection *fd);
int FlowKeyExtendedInitFromMbuf(
        FlowKey *flow_key, struct FlowKeyDirection *fd, struct rte_mbuf *mbuf);

int DPDKBypassManagerAssistantInit(ThreadVars *th_v, struct timespec *curtime, void *data);
int DPDKCheckBypassMessages(
        ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data);

#endif /* HAVE_DPDK */
#endif // UTIL_DPDK_PREFILTER_H
