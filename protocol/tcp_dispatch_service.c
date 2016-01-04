#include <stdlib.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_dispatch_service.h"

static u_int
dispatchHash (const char *key1, const char *key2) {
    u_int sum, hash = 0;
    u_int seed = 16777619;
    const char *tmp;

    if (strlen (key1) < strlen (key2)) {
        tmp = key1;
        key1 = key2;
        key2 = tmp;
    }

    while (*key2) {
        hash *= seed;
        sum = *key1 + *key2;
        hash ^= sum;
        key1++;
        key2++;
    }

    while (*key1) {
        hash *= seed;
        hash ^= (size_t) (*key1);
        key1++;
    }

    return hash;
}

/**
 * @brief Dispatch timestamp and ip packet to specific tcp
 *        packet process service thread.
 *
 * @param iph -- ip packet to dispatch
 * @param tm -- capture timestamp to dispatch
 */
static void
tcpPacketDispatch (iphdrPtr iph, timeValPtr tm) {
    int ret;
    u_int hash;
    u_int ipPktLen;
    tcphdrPtr tcph;
    char ipSrcStr [16], ipDestStr [16];
    char key1 [32], key2 [32];
    zframe_t *frame;
    void *tcpPktSendSock = NULL;

    ipPktLen = ntohs (iph->ipLen);

    tcph = (tcphdrPtr) ((u_char *) iph + (iph->iphLen * 4));
    inet_ntop (AF_INET, (void *) &iph->ipSrc, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &iph->ipDest, ipDestStr, sizeof (ipDestStr));
    snprintf (key1, sizeof (key1), "%s:%d", ipSrcStr, ntohs (tcph->source));
    snprintf (key2, sizeof (key2), "%s:%d", ipDestStr, ntohs (tcph->dest));

    hash = dispatchHash (key1, key2);
    tcpPktSendSock = getTcpPktSendSock (hash % getTcpProcessThreadsNum ());

    /* Send tm zframe*/
    frame = zframe_new (tm, sizeof (timeVal));
    if (frame == NULL) {
        LOGE ("Create timestamp zframe error.\n");
        return;
    }
    ret = zframe_send (&frame, tcpPktSendSock, ZFRAME_MORE);
    if (ret < 0) {
        LOGE ("Send tm zframe error.\n");
        return;
    }

    /* Send ip packet */
    frame = zframe_new (iph, ipPktLen);
    if (frame == NULL) {
        LOGE ("Create ip packet zframe error.");
        return;
    }
    ret = zframe_send (&frame, tcpPktSendSock, 0);
    if (ret < 0) {
        LOGE ("Send ip packet zframe error.\n");
        return;
    }
}

/*
 * Tcp packet dispatch service.
 * Read ip packet send by remote/local node, then dispatch ip
 * packet to local specific tcpProcessService thread.
 */
void *
tcpDispatchService (void *args) {
    int ret;
    void *tcpPktDispatchRecvSock;
    zframe_t *tmFrame = NULL;
    zframe_t *pktFrame = NULL;
    iphdrPtr iph;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Display task schedule policy info */
    displayTaskSchedPolicyInfo ("TcpDispatchService");

    /* Get tcpPktDispatchRecvSock */
    tcpPktDispatchRecvSock = getTcpPktDispatchRecvSock ();

    while (!taskShouldExit ()) {
        /* Receive timestamp zframe */
        if (tmFrame == NULL) {
            tmFrame = zframe_recv (tcpPktDispatchRecvSock);
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
        pktFrame = zframe_recv (tcpPktDispatchRecvSock);
        if (pktFrame == NULL) {
            if (!taskShouldExit ())
                LOGE ("Receive ip packet zframe with fatal error.\n");
            zframe_destroy (&tmFrame);
            break;
        } else if (zframe_more (pktFrame)) {
            zframe_destroy (&tmFrame);
            tmFrame = pktFrame;
            pktFrame = NULL;
            continue;
        }

        iph = (iphdrPtr) zframe_data (pktFrame);
        /* Dispatch ip packet and tmFrame */
        switch (iph->ipProto) {
            case IPPROTO_TCP:
                tcpPacketDispatch (iph, (timeValPtr) zframe_data (tmFrame));
                break;

            default:
                break;
        }

        /* Free zframe */
        zframe_destroy (&tmFrame);
        zframe_destroy (&pktFrame);
    }

    LOGI ("TcpDispatchService will exit ... .. .\n");
    destroyLogContext ();
exit:
    if (!taskShouldExit ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
