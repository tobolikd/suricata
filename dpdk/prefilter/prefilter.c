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
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */

#define _POSIX_C_SOURCE 200809L
#define CLS 64 // sysconf(_SC_LEVEL1_DCACHE_LINESIZE)
#include <getopt.h>

#include "prefilter.h"
#include "util-prefilter.h"
#include "logger.h"
#include "logger-basic.h"

#include "dev-conf.h"
#include "dev-conf-suricata.h"
#include "lcores-manager.h"
#include "stats.h"

struct prefilter_args {
    char *conf_path;
};

static void EalInit(int *argc, char ***argv)
{
    int args;

    rte_log_set_global_level(RTE_LOG_WARNING);
    args = rte_eal_init(*argc, *argv);
    if (args < 0) {
        fprintf(stderr, "rte_eal_init() has failed: %d\n", args);
        exit(EXIT_FAILURE);
    }
    *argc -= args;
    *argv += args;

    if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
        fprintf(stderr, "invalid process type, primary required\n");
        rte_eal_cleanup();
        exit(EXIT_FAILURE);
    }
}

static void PrintUsage(char *prog)
{

    printf("\t-c <path>                            : path to configuration file\n");
    printf("\t--config-path <path>                            : path to configuration file\n");
}

static int ArgsParse(int argc, char *argv[], struct prefilter_args *args)
{
    int opt;

    // clang-format off
struct option long_opts[] = {
#ifdef HAVE_DPDK
    {"config-path", required_argument, 0, 0},
#endif
};
    // clang-format on

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp((long_opts[option_index]).name, "config-path") == 0) {
                    args->conf_path = optarg;
                    break;
                }
                PrintUsage(argv[0]);
                return -EXIT_FAILURE;
            case 'c':
                args->conf_path = optarg;
                break;
            default:
                PrintUsage(argv[0]);
                return -EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    int ret;
    struct resource_ctx ctx = {0};
    struct prefilter_args args;
    struct pf_stats *stats;
    EalInit(&argc, &argv);
    ret = ArgsParse(argc, argv, &args);
    if (ret != 0)
        goto cleanup;

    SignalInit();

    LoggerInitOps(logger_basic_ops);

//    dev_conf_suricata_ops
    DevConfInit(dev_conf_suricata_ops);
    ret = DevConfConfigureBy((void *)args.conf_path);
    if (ret != 0) {
        return ret;
    }
    Log().info("Configured");

    ret = DevConfRingsInit(&ctx);
    if (ret != 0)
        return ret;

    ret = StatsInit(&stats);
    if (ret != 0)
        return ret;

    ret = LcoreManagerRunWorkers(stats);
    if (ret != 0)
        return ret;

    rte_eal_mp_wait_lcore();

    StatsExitLog(stats);



//    LcoreManagerRunWorkers()
    // init lcore structure

    // RingListSpawnWorkers()
    // spawn workers

    // RingListSpawnWorker()
    // workers init (alloc resources on the main, so if any error happens, you can free them)
    // on spawn of all workers release resource buffer
    //
    //
    //worker
    // create worker struct that includes
    // ring entry, atomic threads state, atomic state_sync_cnt, assigned queue, assigned port number
    // worker does not alloc resources mostly
    // maybe only somehow initializes them
    // Workers should be unified again I guess. (to avoid complications)
    // then increase state_sync_cnt and wait based on the threads_state enum(?)
    // this is Suricata state, check those out. PTV_KILL and similar.
    // maybe each worker will have the thread state variable...

    // On deinit...
    // main thread sets thread_state to stop
    // thread deinit starts (probably nothing, maybe stats export, cleaning up the tables but not freeing)
    //
    // Check thread sync from Suricata (e.g. TmThreadsCheckFlag, THV_KILL etc.)

    // maybe main thread could hold all resources so those can be freed from one place...





    //




    //    ConfigurerInit();
    //    configure(argc, argv); loads config

cleanup:
    rte_eal_cleanup();

    return 0;
}