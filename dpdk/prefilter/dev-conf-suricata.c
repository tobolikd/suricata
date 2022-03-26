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

#define PCRE2_CODE_UNIT_WIDTH 8
#define _POSIX_C_SOURCE       200809L
#include <string.h>
#include <netinet/in.h>
#include <dirent.h>

#include "dev-conf-suricata.h"
#include "dev-conf.h"
#include "logger.h"

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-atomic.h"
#include "tm-threads-common.h"
#include "threads.h"
#include "util-device.h"
#include "util-debug.h"
#include "util-dpdk.h"

enum PFOpMode {
    PIPELINE,
    IDS,
    IPS,
};

struct ring_conf {
    const char *name_base;
    uint32_t elem_cnt;
};

struct nic_conf {
    char iface[RTE_ETH_NAME_MAX_LEN];
    uint16_t port_id;
    uint16_t socket_id;
    /* Ring mode settings */
    struct rte_ring **rx_rings;
    struct rte_ring **tx_rings;
    /* End of ring mode settings */
    /* DPDK flags */
    uint32_t flags;
    /* set maximum transmission unit of the device in bytes */
    uint16_t mtu;
    uint16_t nb_rx_queues;
    uint16_t nb_rx_desc;
    uint16_t nb_tx_queues;
    uint16_t nb_tx_desc;
    uint32_t mempool_size;
    uint32_t mempool_cache_size;
    struct rte_mempool *pkt_mempool;
};

struct table_conf {
    const char *name;
    uint32_t entries;
};

struct mempool_conf {
    const char *name;
    uint32_t entries;
    uint16_t cache_entries;
};

struct msgs_conf {
    struct ring_conf taskring;
    struct ring_conf resultring;
    struct mempool_conf mempool;
};

struct ring_entry_conf {
    struct ring_conf mainring;
    enum PFOpMode opmode;
    uint16_t rx_rings_cnt;
    uint16_t pf_cores_cnt;
    const char *port_pcie1;
    const char *port_pcie2;
    struct nic_conf nic_conf;
    struct msgs_conf msgs;
    struct table_conf bypass_table_base;
    struct mempool_conf bypass_mempool;

};

struct RingConfigAttributes {
    const char *ring_name_base;
    const char *ring_elems;
};

struct NicConfigAttributes {
    const char *promisc;
    const char *multicast;
    const char *rss;
    const char *checksum_checks_offload;
    const char *mtu;
    const char *mempool_size;
    const char *mempool_cache_size;
    const char *rx_descriptors;
    const char *tx_descriptors;
};

struct MempoolConfigAttributes {
    const char *mp_name_base;
    const char *mp_entries;
    const char *mp_cache_entries;
};

struct RingEntryAttributes {
    struct RingConfigAttributes main_ring;
    const char *prefilter_lcores;
    const char *secondary_app_lcores;
    const char *op_mode;
    const char *bypass_table_name;
    const char *bypass_table_entries;
    const char *bypass_mp_name;
    const char *bypass_mp_entries;
    const char *bypass_mp_cache_entries;
    const char *port_pcie1;
    const char *port_pcie2;
    struct NicConfigAttributes nic_config;
    struct RingConfigAttributes task_ring;
    struct RingConfigAttributes results_ring;
    struct MempoolConfigAttributes msgs_mp;
};

#define PROMISC_ENABLED 1 << 0
#define MULTICAST_ENABLED 1 << 1
#define RSS_ENABLED 1 << 2
#define CHSUM_OFFLOAD_ENABLED 1 << 3

#define NIC_CONFIG_PREFIX "nic-config."
#define TASK_RING_PREFIX "task-ring."
#define RESULTS_RING_PREFIX "results-ring."
#define MSG_MEMPOOL_PREFIX "message-mempool."

const struct RingEntryAttributes pf_yaml = {
    .main_ring = {
            .ring_name_base = NULL, // value obtained from the root value
            .ring_elems = "elements"
    },
    .prefilter_lcores = "pf-lcores",
    .secondary_app_lcores = "secondary-app-lcores",
    .op_mode = "op-mode",
    .bypass_table_name = "bypass-table-name-base",
    .bypass_table_entries = "bypass-table-entries",
    .bypass_mp_name = "bypass-mempool-name",
    .bypass_mp_entries = "bypass-mempool-entries",
    .bypass_mp_cache_entries = "bypass-mempool-cache-entries",
    .port_pcie1 = "port-pcie1",
    .port_pcie2 = "port-pcie2",
    .nic_config = {
        .promisc = NIC_CONFIG_PREFIX "promisc",
        .multicast = NIC_CONFIG_PREFIX "multicast",
        .rss = NIC_CONFIG_PREFIX "rss",
        .checksum_checks_offload = NIC_CONFIG_PREFIX "checksum-checks-offload",
        .mtu = NIC_CONFIG_PREFIX "mtu",
        .mempool_size = NIC_CONFIG_PREFIX "mempool-size",
        .mempool_cache_size = NIC_CONFIG_PREFIX "mempool-cache-size",
        .rx_descriptors = NIC_CONFIG_PREFIX "rx-descriptors",
        .tx_descriptors = NIC_CONFIG_PREFIX "tx-descriptors",
    },
    .task_ring = {
            .ring_name_base = TASK_RING_PREFIX "name",
            .ring_elems = TASK_RING_PREFIX "elements",
    },
    .results_ring = {
            .ring_name_base = RESULTS_RING_PREFIX "name", // loaded from the root
            .ring_elems = RESULTS_RING_PREFIX "elements",
    },
    .msgs_mp = {
            .mp_name_base = MSG_MEMPOOL_PREFIX "name",
            .mp_entries = MSG_MEMPOOL_PREFIX "entries",
            .mp_cache_entries = MSG_MEMPOOL_PREFIX "cache-entries",
    },
};

#define PREFILTER_CONFIG_OPERATION_MODE_PIPELINE   "pipeline"
#define PREFILTER_CONFIG_OPERATION_MODE_IPS   "ips"
#define PREFILTER_CONFIG_OPERATION_MODE_IDS   "ids"

#define PREFILTER_CONFIG_DEFAULT_OPERATION_MODE              PREFILTER_CONFIG_OPERATION_MODE_IDS
#define PREFILTER_CONFIG_DEFAULT_MEMPOOL_SIZE                65535
#define PREFILTER_CONFIG_DEFAULT_MEMPOOL_CACHE_SIZE          "auto"
#define PREFILTER_CONFIG_DEFAULT_RX_DESCRIPTORS              1024
#define PREFILTER_CONFIG_DEFAULT_TX_DESCRIPTORS              1024
#define PREFILTER_CONFIG_DEFAULT_MTU                         1500
#define PREFILTER_CONFIG_DEFAULT_PROMISCUOUS_MODE            1
#define PREFILTER_CONFIG_DEFAULT_MULTICAST_MODE              1
#define PREFILTER_CONFIG_DEFAULT_CHECKSUM_VALIDATION         1
#define PREFILTER_CONFIG_DEFAULT_CHECKSUM_VALIDATION_OFFLOAD 1
#define PREFILTER_CONFIG_DEFAULT_COPY_MODE                   "none"
#define PREFILTER_CONFIG_DEFAULT_COPY_INTERFACE              "none"

#define PF_NODE_NAME_MAX 1024

/**
 * \brief Find the configuration node for a specific item.

 * \param node The node to start looking for the item configuration.
 * \param iface The name of the interface to find the config for.
 */
static ConfNode *ConfFindItemConfig(ConfNode *node, const char *itemname, const char *iface)
{
    ConfNode *if_node, *item;
    TAILQ_FOREACH (if_node, &node->head, next) {
        TAILQ_FOREACH (item, &if_node->head, next) {
            if (strcmp(item->name, itemname) == 0 && strcmp(item->val, iface) == 0) {
                return if_node;
            }
        }
    }

    return NULL;
}

static ConfNode *ConfNodeLookupDescendant(const ConfNode *base, const char *name)
{
    ConfNode *node = (ConfNode *)base;
    char node_name[PF_NODE_NAME_MAX];
    char *key;
    char *next;

    if (strlcpy(node_name, name, sizeof(node_name)) >= sizeof(node_name)) {
        SCLogError(SC_ERR_CONF_NAME_TOO_LONG,
                "Configuration name too long: %s", name);
        return NULL;
    }

    key = node_name;
    do {
        if ((next = strchr(key, '.')) != NULL)
            *next++ = '\0';
        node = ConfNodeLookupChild(node, key);
        key = next;
    } while (next != NULL && node != NULL);

    return node;
}

static int ConfGetDescendantValue(const ConfNode *base, const char *name, const char **vptr)
{
    ConfNode *node = ConfNodeLookupDescendant(base, name);

    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = node->val;
        return 1;
    }
}

static int ConfGetDescendantValueInt(const ConfNode *base, const char *name, intmax_t *val)
{
    const char *strval = NULL;
    intmax_t tmpint;
    char *endptr;

    if (ConfGetDescendantValue(base, name, &strval) == 0)
        return 0;
    errno = 0;
    tmpint = strtoimax(strval, &endptr, 0);
    if (strval[0] == '\0' || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "malformed integer value "
                                                   "for %s with base %s: '%s'", name, base->name, strval);
        return 0;
    }
    if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN)) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "integer value for %s with "
                                                   " base %s out of range: '%s'", name, base->name, strval);
        return 0;
    }

    *val = tmpint;
    return 1;
}

static int ConfGetDescendantValueBool(const ConfNode *base, const char *name, int *val)
{
    const char *strval = NULL;

    *val = 0;
    if (ConfGetDescendantValue(base, name, &strval) == 0)
        return 0;

    *val = ConfValIsTrue(strval);

    return 1;
}


int DevConfSuricataLoadRingEntryConf(ConfNode *re, struct ring_entry_conf *rc)
{
    const char *entry_str = NULL;
    intmax_t entry_int;
    int retval, entry_bool;
    const char *entry_char;

    rc->mainring.name_base = re->val;

    retval = ConfGetChildValueInt(re, pf_yaml.main_ring.ring_elems, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.main_ring.ring_elems);
        return -EXIT_FAILURE;
    } else {
        rc->mainring.elem_cnt = entry_int;
    }

    retval = ConfGetChildValueInt(re, pf_yaml.prefilter_lcores, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.prefilter_lcores);
        return -EXIT_FAILURE;
    } else {
        rc->pf_cores_cnt = entry_int;
    }

    retval = ConfGetChildValueInt(re, pf_yaml.secondary_app_lcores, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.secondary_app_lcores);
        return -EXIT_FAILURE;
    } else {
        rc->rx_rings_cnt = entry_int;
    }

    retval = ConfGetChildValue(re, pf_yaml.op_mode, &entry_char);
    if (retval != 1 || entry_char == NULL) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.op_mode);
        return -EXIT_FAILURE;
    } else {
        if (strcmp(entry_char, PREFILTER_CONFIG_OPERATION_MODE_PIPELINE) == 0)
            rc->opmode = PIPELINE;
        else if (strcmp(entry_char, PREFILTER_CONFIG_OPERATION_MODE_IDS) == 0)
            rc->opmode = IDS;
        else if (strcmp(entry_char, PREFILTER_CONFIG_OPERATION_MODE_IPS) == 0)
            rc->opmode = IPS;
        else {
            Log().error(ENOENT, "Unable to read value of %s", pf_yaml.op_mode);
            return -EXIT_FAILURE;
        }
    }

    retval = ConfGetChildValue(re, pf_yaml.bypass_table_name, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_table_name);
        return -EXIT_FAILURE;
    } else {
        rc->bypass_table_base.name = entry_char;
    }

    retval = ConfGetChildValueInt(re, pf_yaml.bypass_table_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_table_entries);
        return -EXIT_FAILURE;
    } else {
        rc->bypass_table_base.entries = entry_int;
    }

    retval = ConfGetChildValue(re, pf_yaml.bypass_mp_name, &entry_char);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_mp_name);
        return -EXIT_FAILURE;
    } else {
        if (entry_char == NULL || entry_char[0] == '\0' || strcmp(entry_char, "none") == 0)
            rc->bypass_mempool.name = NULL;
        else
            rc->bypass_mempool.name = entry_char;
    }

    retval = ConfGetChildValueInt(re, pf_yaml.bypass_mp_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_mp_entries);
        return -EXIT_FAILURE;
    } else {
        rc->bypass_mempool.entries = entry_int;
    }

    retval = ConfGetChildValueInt(re, pf_yaml.bypass_mp_cache_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_mp_cache_entries);
        return -EXIT_FAILURE;
    } else {
        rc->bypass_mempool.cache_entries = entry_int;
    }

    retval = ConfGetChildValue(re, pf_yaml.port_pcie1, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.port_pcie1);
        return -EXIT_FAILURE;
    } else {
        rc->port_pcie1 = entry_char;
    }

    retval = ConfGetChildValue(re, pf_yaml.port_pcie2, &entry_char);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.port_pcie2);
        return -EXIT_FAILURE;
    } else {
        if (entry_char == NULL || entry_char[0] == '\0' || strcmp(entry_char, "none") == 0)
            rc->port_pcie2 = NULL;
        else
            rc->port_pcie2 = entry_char;
    }

    retval = ConfGetDescendantValueBool(re, pf_yaml.nic_config.promisc, &entry_bool);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.promisc);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.flags |= PROMISC_ENABLED;
    }

    retval = ConfGetDescendantValueBool(re, pf_yaml.nic_config.multicast, &entry_bool);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.multicast);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.flags |= MULTICAST_ENABLED;
    }

    retval = ConfGetDescendantValueBool(re, pf_yaml.nic_config.rss, &entry_bool);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.rss);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.flags |= RSS_ENABLED;
    }

    retval = ConfGetDescendantValueBool(re, pf_yaml.nic_config.checksum_checks_offload, &entry_bool);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.checksum_checks_offload);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.flags |= CHSUM_OFFLOAD_ENABLED;
    }

    retval = ConfGetDescendantValueInt(re, pf_yaml.nic_config.mtu, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.mtu);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.mtu = entry_int;
    }

    retval = ConfGetDescendantValueInt(re, pf_yaml.nic_config.mempool_size, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.mempool_size);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.mempool_size = entry_int;
    }

    retval = ConfGetDescendantValueInt(re, pf_yaml.nic_config.mempool_cache_size, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.mempool_cache_size);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.mempool_cache_size = entry_int;
    }

    retval = ConfGetDescendantValueInt(re, pf_yaml.nic_config.rx_descriptors, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.rx_descriptors);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.nb_rx_desc = entry_int;
    }

    retval = ConfGetDescendantValueInt(re, pf_yaml.nic_config.tx_descriptors, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.tx_descriptors);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.nb_tx_desc = entry_int;
    }

    retval = ConfGetDescendantValue(re, pf_yaml.task_ring.ring_name_base, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.task_ring.ring_name_base);
        return -EXIT_FAILURE;
    } else {
        rc->msgs.taskring.name_base = entry_char;
    }

    retval = ConfGetDescendantValueInt(re, pf_yaml.task_ring.ring_elems, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.task_ring.ring_elems);
        return -EXIT_FAILURE;
    } else {
        rc->msgs.taskring.elem_cnt = entry_int;
    }

    retval = ConfGetDescendantValue(ConfGetRootNode(), pf_yaml.results_ring.ring_name_base, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.results_ring.ring_name_base);
        return -EXIT_FAILURE;
    } else {
        rc->msgs.resultring.name_base = entry_char;
    }

    retval = ConfGetDescendantValueInt(ConfGetRootNode(), pf_yaml.results_ring.ring_elems, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.results_ring.ring_elems);
        return -EXIT_FAILURE;
    } else {
        rc->msgs.resultring.elem_cnt = entry_int;
    }

    retval = ConfGetDescendantValue(ConfGetRootNode(), pf_yaml.msgs_mp.mp_name_base, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.msgs_mp.mp_name_base);
        return -EXIT_FAILURE;
    } else {
        rc->msgs.mempool.name = entry_char;
    }

    retval = ConfGetDescendantValueInt(ConfGetRootNode(), pf_yaml.msgs_mp.mp_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.msgs_mp.mp_entries);
        return -EXIT_FAILURE;
    } else {
        rc->msgs.mempool.entries = entry_int;
    }

    retval = ConfGetDescendantValueInt(ConfGetRootNode(), pf_yaml.msgs_mp.mp_cache_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.msgs_mp.mp_cache_entries);
        return -EXIT_FAILURE;
    } else {
        rc->msgs.mempool.cache_entries = entry_int;
    }

    return 0;
}

int DevConfSuricataConfigureBy(void *conf)
{
    int retval;
    const char *conf_path = conf;
    char *interfaces_selector = "rings";
    char *itemname = "ring";
    const char *live_dev_c = NULL;
    int ldev;

    SCLogInitLogModule(NULL);
    /* Initialize the Suricata configuration module. */
    ConfInit();

    retval = ConfYamlLoadFile(conf_path);
    if (retval != 0) {
        Log().error(-retval, "Configuration not good");
        return retval;
    }

    retval = LiveBuildDeviceListCustom(interfaces_selector, itemname);
    if (retval == 0)
        Log().error(ENODEV, "no ring found");

    Log().info("Found %d rings", retval);
    LiveDeviceFinalize();

    RingListInitHead();

    int nlive = LiveGetDeviceCount();
    for (ldev = 0; ldev < nlive; ldev++) {
        live_dev_c = LiveGetDeviceName(ldev);

        ConfNode *rings_node = ConfGetNode("rings");
        ConfNode *ring_entry = ConfFindItemConfig(rings_node, itemname, live_dev_c);
        if (ring_entry == NULL) {
            SCLogNotice("Unable to find configuration for %s \"%s\"", itemname, live_dev_c);
        }

        struct ring_entry_conf rc;
        retval = DevConfSuricataLoadRingEntryConf(ring_entry, &rc);
        if (retval != 0) {
            return retval;
        }

        //        DevConfSuricataLoadRingEntry()

        //        conf_yaml_port_entry_load(iface_node, default_node, port_entry);

        //        RingListAddConf(void *ring_conf)
    }
}

struct DeviceConfigurer dev_conf_suricata_ops = { .ConfigureBy = DevConfSuricataConfigureBy

};