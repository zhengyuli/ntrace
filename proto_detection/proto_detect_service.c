#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include "config.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "netdev.h"
#include "zmq_hub.h"
#include "app_service_manager.h"
#include "task_manager.h"
#include "ip.h"
#include "tcp.h"
#include "raw_packet.h"
#include "ip_packet.h"
#include "tcp_packet.h"
#include "analysis_record.h"
#include "proto_detect_service.h"

#define PACKETS_OF_PROTO_DETECT_SCAN 1000
#define INTERVAL_AFTER_PROTO_DETECT_SCAN 5

__thread void *topologyEntrySendSock = NULL;
__thread void *appServiceSendSock = NULL;

static void
updateFilterForSniff (void) {
    int ret;
    char *filter;

    /* Update application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL)
        LOGE ("Get application services filter error.\n");
    else {
        ret = updateNetDevFilterForSniff (filter);
        if (ret < 0)
            LOGE ("Update application services filter error.\n");
        else
            LOGI ("Update application services filter with:\n%s\n", filter);

        free (filter);
    }
}

static void
protoDetectCallback (tcpProcessCallbackArgsPtr callbackArgs) {
    switch (callbackArgs->type) {
        case PUBLISH_TOPOLOGY_ENTRY:
            publishAnalysisRecord (topologyEntrySendSock, (char *) callbackArgs->args);
            break;

        case PUBLISH_APP_SERVICE:
            if (getPropertiesSniffLive () && getPropertiesAutoAddService ())
                updateFilterForSniff ();
            publishAnalysisRecord (appServiceSendSock, (char *) callbackArgs->args);
            break;

        default:
            LOGE ("Wrong proto detect callback args type.\n");
            break;
    }
}

/*
 * Proto detect service.
 * Capture raw packets from pcap file or mirror interface,
 * then do ip defragment and tcp packet process to detect
 * application level proto.
 */
void *
protoDetectService (void *args) {
    int ret;
    pcap_t * pcapDev;
    int datalinkType;
    struct pcap_pkthdr *capPktHdr;
    u_char *rawPkt;
    boolean captureLive;
    u_long_long packetsScanned = 0;
    timeVal captureTime;
    iphdrPtr iph, newIphdr;
    boolean exitNormally = False;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Display task schedule policy info */
    displayTaskSchedPolicyInfo ("ProtoDetectService");

    pcapDev = getNetDevPcapDescForProtoDetection ();
    datalinkType = getNetDevDatalinkTypeForProtoDetection ();
    topologyEntrySendSock = getTopologyEntrySendSock ();
    appServiceSendSock = getAppServiceSendSock ();

    /* Update proto detection filter */
    ret = updateNetDevFilterForProtoDetection ("tcp");
    if (ret < 0) {
        LOGE ("Update application services filter error.\n");
        goto destroyLogContext;
    }

    /* Init ip context */
    ret = initIpContext (True);
    if (ret < 0) {
        LOGE ("Init ip context error.\n");
        goto destroyLogContext;
    }

    /* Init tcp context */
    ret = initTcpContext (True, protoDetectCallback);
    if (ret < 0) {
        LOGE ("Init tcp context error.\n");
        goto destroyIpContext;
    }

    captureLive = getPropertiesSniffLive ();

    while (!taskShouldExit ()) {
        ret = pcap_next_ex (pcapDev, &capPktHdr, (const u_char **) &rawPkt);
        if (ret == 1) {
            /* Filter out incomplete raw packet */
            if (capPktHdr->caplen != capPktHdr->len)
                continue;

            packetsScanned ++;

            if (captureLive && packetsScanned % PACKETS_OF_PROTO_DETECT_SCAN == 0) {
                LOGD ("Pause ProtoDetectService after scanning packets: %llu.\n", packetsScanned);
                sleep (INTERVAL_AFTER_PROTO_DETECT_SCAN);

                /* Reset ip context */
                resetIpContext ();

                /* Reset tcp context */
                resetTcpContext ();

                LOGD ("Resume ProtoDetectService.\n");
                continue;
            }

            /* Get ip packet */
            iph = (iphdrPtr) getIpPacket (rawPkt, datalinkType);
            if (iph == NULL)
                continue;

            /* Get packet capture timestamp */
            captureTime.tvSec = htonll (capPktHdr->ts.tv_sec);
            captureTime.tvUsec = htonll (capPktHdr->ts.tv_usec);

            /* Ip packet defrag process */
            ret = ipDefragProcess (iph, &captureTime, &newIphdr);
            if (ret < 0)
                LOGE ("Ip packet defragment error.\n");
            else if (newIphdr) {
                switch (newIphdr->ipProto) {
                    /* Tcp packet process */
                    case IPPROTO_TCP:
                        tcpProcess (newIphdr, &captureTime);
                        break;

                    default:
                        break;
                }

                /* Free new ip packet after defragment */
                if (newIphdr != iph)
                    free (newIphdr);
            }
        } else if (ret == -1) {
            LOGE ("Capture raw packets for proto detection with fatal error.\n");
            break;
        } else if (ret == -2) {
            if (!captureLive)
                zstr_send (getProtoDetectionStatusSendSock (),
                           "\n"
                           "******************************************\n"
                           "Proto detection complete.\n"
                           "******************************************\n");
            exitNormally = True;
            break;
        }
    }

    LOGI ("ProtoDetectService will exit ... .. .\n");
    destroyTcpContext ();
destroyIpContext:
    destroyIpContext ();
destroyLogContext:
    destroyLogContext ();
exit:
    if (exitNormally)
        sendTaskStatus (TASK_STATUS_EXIT_NORMALLY);
    else if (!taskShouldExit ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
