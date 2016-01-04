#define _GNU_SOURCE
#include <stdlib.h>
#include <sched.h>
#include <pthread.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "ip.h"
#include "tcp_packet.h"
#include "analysis_record.h"
#include "tcp_process_service.h"

/* Tcp breakdown send sock */
static __thread void *tcpBreakdownSendSock = NULL;

static void
tcpProcessCallback (tcpProcessCallbackArgsPtr callbackArgs) {
    switch (callbackArgs->type) {
        case PUBLISH_TCP_BREAKDOWN:
            publishAnalysisRecord (tcpBreakdownSendSock, (char *) callbackArgs->args);
            break;

        default:
            LOGE ("Wrong tcp process callback args type.\n");
            break;
    }
}

/*
 * Tcp packet process service.
 * Read ip packets send by ipProcessService, then do tcp
 * process and then send tcp breakdown to analysis record
 * service.
 */
void *
tcpProcessService (void *args) {
    int ret;
    u_int dispatchIndex;
    cpu_set_t cpuset;
    void *tcpPktRecvSock;
    zframe_t *tmFrame = NULL;
    zframe_t *ipPktFrame = NULL;
    timeValPtr tm;
    iphdrPtr iph;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    dispatchIndex = *((u_int *) args);
    tcpPktRecvSock = getTcpPktRecvSock (dispatchIndex);
    tcpBreakdownSendSock = getTcpBreakdownSendSock (dispatchIndex);

    /* Bind tcpProcessService to CPU# */
    CPU_ZERO (&cpuset);
    CPU_SET (dispatchIndex, &cpuset);
    ret = pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t), &cpuset);
    if (ret < 0) {
        LOGE ("Binding tcpProcessService:%u to CPU%u error.\n", dispatchIndex, dispatchIndex);
        goto destroyLogContext;
    }
    LOGI ("Binding tcpProcessService:%u to CPU%u success.\n", dispatchIndex, dispatchIndex);

    /* Display task schedule policy info */
    displayTaskSchedPolicyInfo ("TcpProcessService");

    /* Init tcp context */
    ret = initTcpContext (False, tcpProcessCallback);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroyLogContext;
    }

    while (!taskShouldExit ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktRecvSock);
            if (tmFrame == NULL) {
                if (!taskShouldExit ())
                    LOGE ("Receive timestamp zframe with fatal error.\n");
                break;
            } else if (!zframe_more (tmFrame)) {
                zframe_destroy (&tmFrame);
                continue;
            }
        }

        /* Receive ip packet zframe */
        ipPktFrame = zframe_recv (tcpPktRecvSock);
        if (ipPktFrame == NULL) {
            if (!taskShouldExit ())
                LOGE ("Receive ip packet zframe with fatal error.\n");
            zframe_destroy (&tmFrame);
            break;
        } else if (zframe_more (ipPktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = ipPktFrame;
            ipPktFrame = NULL;
            continue;
        }

        tm = (timeValPtr) zframe_data (tmFrame);
        iph = (iphdrPtr) zframe_data (ipPktFrame);

        /* Do tcp process */
        tcpProcess (iph, tm);

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&ipPktFrame);
    }

    LOGI ("TcpProcessService will exit ... .. .\n");
    destroyTcpContext ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (!taskShouldExit ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
