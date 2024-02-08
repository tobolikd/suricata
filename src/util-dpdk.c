/* Copyright (C) 2021 - 2022 Open Information Security Foundation
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

#ifndef UTIL_DPDK_C
#define UTIL_DPDK_C

#include "suricata.h"
#include "flow-bypass.h"
#include "decode.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include "util-byte.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-i40e.h"

uint32_t ArrayMaxValue(const uint32_t *arr, uint16_t arr_len)
{
    uint32_t max = 0;
    for (uint16_t i = 0; i < arr_len; i++) {
        max = MAX(arr[i], max);
    }
    return max;
}

// Used to determine size for memory allocation of a string
uint8_t CountDigits(uint32_t n)
{
    uint8_t digits_cnt = 0;
    if (n == 0)
        return 1;

    while (n != 0) {
        n = n / 10;
        digits_cnt++;
    }
    return digits_cnt;
}

void DPDKCleanupEAL(void)
{
#ifdef HAVE_DPDK
    if (run_mode == RUNMODE_DPDK && rte_eal_process_type() == RTE_PROC_PRIMARY) {
        int retval = rte_eal_cleanup();
        if (retval != 0)
            SCLogError("EAL cleanup failed: %s", strerror(-retval));
    }
#endif
}

#ifdef HAVE_DPDK
void DPDKCloseDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
    int retval;
    if (run_mode == RUNMODE_DPDK && rte_eal_process_type() == RTE_PROC_PRIMARY) {
        uint16_t port_id;
        retval = rte_eth_dev_get_port_by_name(ldev->dev, &port_id);
        if (retval < 0) {
            SCLogError("%s: failed get port id, error: %s", ldev->dev, rte_strerror(-retval));
            return;
        }

        SCLogPerf("%s: closing device", ldev->dev);
        rte_eth_dev_close(port_id);
    }
#endif
}

void DPDKFreeDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    if (run_mode == RUNMODE_DPDK) {
        SCLogDebug("%s: releasing packet mempool", ldev->dev);
        rte_mempool_free(ldev->dpdk_vars.pkt_mp);
    }
}
#endif /* HAVE_DPDK */

static FILE *HugepagesMeminfoOpen(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        SCLogInfo("Can't analyze hugepage usage: failed to open /proc/meminfo");
    }
    return fp;
}

static void HugepagesMeminfoClose(FILE *fp)
{
    if (fp) {
        fclose(fp);
    }
}

/**
 * Parsing values of meminfo
 *
 * \param fp Opened file pointer for reading of file /proc/meminfo at beginning
 * \param keyword Entry to look for e.g. "HugePages_Free:"
 * \return n Value of the entry
 * \return -1 On error
 *
 */
static int32_t MemInfoParseValue(FILE *fp, const char *keyword)
{
    char path[256], value_str[64];
    int32_t value = -1;

    while (fscanf(fp, "%255s", path) != EOF) {
        if (strcmp(path, keyword) == 0) {
            if (fscanf(fp, "%63s", value_str) == EOF) {
                SCLogDebug("%s: not followed by any number", keyword);
                break;
            }

            if (StringParseInt32(&value, 10, 23, value_str) < 0) {
                SCLogDebug("Failed to convert %s from /proc/meminfo", keyword);
                value = -1;
            }
            break;
        }
    }
    return value;
}

static void MemInfoEvaluateHugepages(FILE *fp)
{
    int32_t free_hugepages = MemInfoParseValue(fp, "HugePages_Free:");
    if (free_hugepages < 0) {
        SCLogInfo("HugePages_Free information not found in /proc/meminfo");
        return;
    }

    rewind(fp);

    int32_t total_hugepages = MemInfoParseValue(fp, "HugePages_Total:");
    if (total_hugepages < 0) {
        SCLogInfo("HugePages_Total information not found in /proc/meminfo");
        return;
    } else if (total_hugepages == 0) {
        SCLogInfo("HugePages_Total equals to zero");
        return;
    }

    float free_hugepages_ratio = (float)free_hugepages / (float)total_hugepages;
    if (free_hugepages_ratio > 0.5) {
        SCLogInfo("%" PRIu32 " of %" PRIu32
                  " of hugepages are free - number of hugepages can be lowered to e.g. %.0lf",
                free_hugepages, total_hugepages, ceil((total_hugepages - free_hugepages) * 1.15));
    }
}

static void MemInfoWith(void (*callback)(FILE *))
{
    FILE *fp = HugepagesMeminfoOpen();
    if (fp) {
        callback(fp);
        HugepagesMeminfoClose(fp);
    }
}

void DPDKEvaluateHugepages(void)
{
    if (run_mode != RUNMODE_DPDK)
        return;

#ifdef HAVE_DPDK
    if (rte_eal_has_hugepages() == 0) { // hugepages disabled
        SCLogPerf("Hugepages not enabled - enabling hugepages can improve performance");
        return;
    }
#endif

    MemInfoWith(MemInfoEvaluateHugepages);
}

#ifdef HAVE_DPDK

/**
 * Retrieves name of the port from port id
 * Not thread-safe
 * @param pid
 * @return static dev_name on success
 */
const char *DPDKGetPortNameByPortID(uint16_t pid)
{
    static char dev_name[RTE_ETH_NAME_MAX_LEN];
    int32_t ret = rte_eth_dev_get_name_by_port(pid, dev_name);
    if (ret < 0) {
        FatalError("Port %d: Failed to obtain port name (err: %s)", pid, rte_strerror(-ret));
    }
    return dev_name;
}

#endif /* HAVE_DPDK */

#ifdef HAVE_DPDK
void DevicePostStartPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0) {
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    }

    // The PMD Driver i40e has a special way to set the RSS, it can be set via rte_flow rules
    // and only after the start of the port
    if (strcmp(driver_name, "net_i40e") == 0)
        i40eDeviceSetRSS(ptv->port_id, ptv->threads);
}

void DevicePreStopPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0) {
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    }

    if (strcmp(driver_name, "net_i40e") == 0) {
#if RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0)
        // Flush the RSS rules that have been inserted in the post start section
        struct rte_flow_error flush_error = { 0 };
        int32_t retval = rte_flow_flush(ptv->port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s: unable to flush rte_flow rules: %s Flush error msg: %s",
                    ptv->livedev->dev, rte_strerror(-retval), flush_error.message);
        }
#endif /* RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0) */
    }
}
#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_C */
