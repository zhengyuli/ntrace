#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <czmq.h>
#include <locale.h>
#include "config.h"
#include "util.h"
#include "signals.h"
#include "properties.h"
#include "option_parser.h"
#include "log.h"
#include "startup_info.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "proto_analyzer.h"
#include "app_service_manager.h"
#include "topology_manager.h"
#include "ownership_manager.h"
#include "netdev.h"
#include "log_service.h"
#include "management_service.h"
#include "raw_capture_service.h"
#include "ip_process_service.h"
#include "icmp_process_service.h"
#include "tcp_dispatch_service.h"
#include "tcp_process_service.h"
#include "analysis_record_service.h"
#include "proto_detect_service.h"

/* nTrace pid file fd */
static int ntracePidFd = -1;

/* Lock pid file for daemon mode */
static int
lockPidFile (void) {
    int ret;
    ssize_t n;
    char buf [16];

    if (!getPropertiesDaemonMode ())
        return 0;

    ntracePidFd = open (NTRACE_SERVICE_PID_FILE, O_CREAT | O_RDWR, 0666);
    if (ntracePidFd < 0)
        return -1;

    ret = flock (ntracePidFd, LOCK_EX | LOCK_NB);
    if (ret < 0) {
        close (ntracePidFd);
        return -1;
    }

    snprintf (buf, sizeof (buf), "%d", getpid ());
    n = safeWrite (ntracePidFd, buf, strlen (buf));
    if (n != strlen (buf)) {
        close (ntracePidFd);
        remove (NTRACE_SERVICE_PID_FILE);
        return -1;
    }
    sync ();

    return 0;
}

/* Unlock pid file for daemon mode */
static void
unlockPidFile (void) {
    if (!getPropertiesDaemonMode ())
        return;

    if (ntracePidFd >= 0) {
        flock (ntracePidFd, LOCK_UN);
        close (ntracePidFd);
        ntracePidFd = -1;
    }
    remove (NTRACE_SERVICE_PID_FILE);
}

/* Start service tasks */
static int
startServices (void) {
    int ret;
    u_int i;

    /* Start logService */
    ret = newNormalTask ("LogService", logService, NULL);
    if (ret < 0) {
        LOGE ("Create logService error.\n");
        goto stopAllTask;
    }

    /* Start managementService */
    ret = newNormalTask ("ManagementService", managementService, NULL);
    if (ret < 0) {
        LOGE ("Create managementService error.\n");
        goto stopAllTask;
    }

    /* Start rawCaptureService */
    ret = newRealTask ("RawCaptureService", rawCaptureService, NULL);
    if (ret < 0) {
        LOGE ("Create rawCaptureService error.\n");
        goto stopAllTask;
    }

    /* Start ipProcessService */
    ret = newRealTask ("IpProcessService", ipProcessService, NULL);
    if (ret < 0) {
        LOGE ("Create ipProcessService error.\n");
        goto stopAllTask;
    }

    /* Start icmpProcessService */
    ret = newRealTask ("IcmpProcessService", icmpProcessService, NULL);
    if (ret < 0) {
        LOGE ("Create icmpProcessService error.\n");
        goto stopAllTask;
    }

    /* Start tcpDispatchService */
    ret = newRealTask ("TcpDispatchService", tcpDispatchService, NULL);
    if (ret < 0) {
        LOGE ("Create tcpDispatchService error.\n");
        goto stopAllTask;
    }

    /* Start tcpProcessServices */
    for (i = 0; i < getTcpProcessThreadsNum (); i++) {
        ret = newRealTask ("TcpProcessService", tcpProcessService,
                           getTcpProcessThreadIDHolder (i));
        if (ret < 0) {
            LOGE ("Create tcpProcessService:%u error.\n", i);
            goto stopAllTask;
        }
    }

    /* Start analysisRecordService */
    ret = newRealTask ("AnalysisRecordService", analysisRecordService, NULL);
    if (ret < 0) {
        LOGE ("Create analysisRecordService error.\n");
        goto stopAllTask;
    }

    /* Start protoDetectService */
    ret = newNormalTask ("ProtoDetectService", protoDetectService, NULL);
    if (ret < 0) {
        LOGE ("Create ProtoDetectService error.\n");
        goto stopAllTask;
    }

    return 0;

stopAllTask:
    stopAllTask ();
    return -1;
}

/* Stop all service tasks */
static void
stopServices (void) {
    stopAllTask ();
}

/* nTrace service entry */
static int
ntraceService (void) {
    int ret;
    zloop_t *loop;
    zmq_pollitem_t pollItem;

    /* Check Permission */
    if (getuid () != 0) {
        fprintf (stderr, "Permission denied, please run as root.\n");
        return -1;
    }

    /* Lock pid file */
    ret = lockPidFile ();
    if (ret < 0) {
        fprintf (stderr, "Lock pid file error.\n");
        return -1;
    }

    /* Setup signal */
    setupSignals ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        ret = -1;
        goto unlockPidFile;
    }

    /* Display startup info */
    displayNtraceStartupInfo ();

    /* Display properties info */
    displayPropertiesDetail ();

    /* Init zmq hub */
    ret = initZmqHub ();
    if (ret < 0) {
        LOGE ("Init zmq hub error.\n");
        ret = -1;
        goto destroyLogContext;
    }

    /* Init task manager */
    ret = initTaskManager ();
    if (ret < 0) {
        LOGE ("Init task manager error.\n");
        ret = -1;
        goto destroyZmqHub;
    }

    /* Init proto analyzer */
    ret = initProtoAnalyzer ();
    if (ret < 0) {
        LOGE ("Init proto context error.\n");
        goto destroyTaskManager;
    }

    /* Init application service manager */
    ret = initAppServiceManager ();
    if (ret < 0) {
        LOGE ("Init application service manager error.\n");
        ret = -1;
        goto destroyProtoAnalyzer;
    }

    /* Init topology manager */
    ret = initTopologyManager ();
    if (ret < 0) {
        LOGE ("Init topology manager error.\n");
        ret = -1;
        goto destroyAppServiceManager;
    }

    /* Init ownership manager */
    ret = initOwnershipManager ();
    if (ret < 0) {
        LOGE ("Init packetOwnership error.\n");
        ret = -1;
        goto destroyTopologyManager;
    }

    /* Init netDev */
    ret = initNetDev ();
    if (ret < 0) {
        LOGE ("Init net device error.\n");
        ret = -1;
        goto destroyOwnershipManager;
    }

    /* Start service tasks */
    ret = startServices ();
    if (ret < 0) {
        LOGE ("Start services error.\n");
        ret = -1;
        goto destroyNetDev;
    }

    /* Create zloop reactor */
    loop = zloop_new ();
    if (loop == NULL) {
        LOGE ("Create zloop error.\n");
        ret = -1;
        goto stopServices;
    }

    /* Init pollItem */
    pollItem.socket = getTaskStatusRecvSock ();
    pollItem.fd = 0;
    pollItem.events = ZMQ_POLLIN;
    /* Register poll item 1 */
    ret = zloop_poller (loop, &pollItem, taskStatusHandler, NULL);
    if (ret < 0) {
        LOGE ("Register pollItem for task status handle error.\n");
        ret = -1;
        goto destroyZloop;
    }

    /* Start zloop */
    ret = zloop_start (loop);
    if (ret)
        LOGE ("nTraceService get error.\n");

    LOGI ("nTraceService will exit ... .. .\n");
destroyZloop:
    zloop_destroy (&loop);
stopServices:
    stopServices ();
destroyNetDev:
    destroyNetDev ();
destroyOwnershipManager:
    destroyOwnershipManager ();
destroyTopologyManager:
    destroyTopologyManager ();
destroyAppServiceManager:
    destroyAppServiceManager ();
destroyProtoAnalyzer:
    destroyProtoAnalyzer ();
destroyTaskManager:
    destroyTaskManager ();
destroyZmqHub:
    destroyZmqHub ();
destroyLogContext:
    destroyLogContext ();
unlockPidFile:
    unlockPidFile ();
    return ret;
}

/* nTrace daemon service entry */
static int
ntraceDaemon (void) {
    pid_t pid, next_pid;
    int stdinfd;
    int stdoutfd;

    if (chdir ("/") < 0) {
        fprintf (stderr, "Change dir error: %s.\n", strerror (errno));
        return -1;
    }

    pid = fork ();
    switch (pid) {
        case 0:
            if ((stdinfd = open ("/dev/null", O_RDONLY)) < 0)
                return -1;

            if ((stdoutfd = open ("/dev/null", O_WRONLY)) < 0) {
                close (stdinfd);
                return -1;
            }

            if (dup2 (stdinfd, STDIN_FILENO) != STDIN_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            if (dup2 (stdoutfd, STDOUT_FILENO) != STDOUT_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            if (dup2 (stdoutfd, STDERR_FILENO) != STDERR_FILENO) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            if (stdinfd > STDERR_FILENO)
                close (stdoutfd);

            if (stdoutfd > STDERR_FILENO)
                close (stdinfd);

            /* Set session id */
            if (setsid () < 0) {
                close (stdoutfd);
                close (stdinfd);
                return -1;
            }

            next_pid = fork ();
            switch (next_pid) {
                case 0:
                    return ntraceService ();

                case -1:
                    return -1;

                default:
                    return 0;
            }

        case -1:
            return -1;

        default:
            return 0;
    }
}

int
main (int argc, char *argv []) {
    int ret;

    /* Set locale */
    setlocale (LC_COLLATE, "");

    ret = parseOptions (argc, argv);
    if (ret < 0) {
        fprintf (stderr, "Parse command line options error.\n");
        ret = -1;
    }

    /* Init properties */
    ret = initProperties (getConfigFile ());
    if (ret < 0) {
        fprintf (stderr, "Init properties error.\n");
        return -1;
    }

    /* Run as daemon or normal process */
    if (getPropertiesDaemonMode ())
        ret = ntraceDaemon ();
    else
        ret = ntraceService ();

    destroyProperties ();
    return ret;
}
