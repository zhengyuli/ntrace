#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <jansson.h>
#include <czmq.h>
#include "config.h"
#include "util.h"
#include "list.h"
#include "hash.h"
#include "atomic.h"
#include "checksum.h"
#include "log.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_options.h"
#include "proto_analyzer.h"
#include "app_service_manager.h"
#include "topology_entry.h"
#include "topology_manager.h"
#include "analysis_record.h"
#include "tcp_packet.h"

/* Tcp stream hash key format string */
#define TCP_STREAM_HASH_KEY_FORMAT "%s:%u:%s:%u"

/* Closing timeout of tcp stream */
#define TCP_STREAM_CLOSING_TIMEOUT 30

/* Tcp stream hash table size */
#define TCP_STREAM_HASH_TABLE_SIZE (1 << 17)
/* Tcp stream hash table size for proto detect */
#define TCP_STREAM_HASH_TABLE_SIZE_FOR_PROTO_DETECT (1 << 12)

/* Tcp receive buffer maxium size = 16MB */
#define TCP_RECEIVE_BUFFER_MAX_SIZE (1 << 24)

/* Tcp expect sequence */
#define EXP_SEQ (snd->firstDataSeq + rcv->count + rcv->urgCount)

/* Tcp streams alloc info for local */
static __thread u_long_long tcpStreamsAllocLocal = 0;

/* Tcp streams free info for local */
static __thread u_long_long tcpStreamsFreeLocal = 0;

/* Tcp stream list */
static __thread listHead tcpStreamList;
/* Tcp stream timeout list */
static __thread listHead tcpStreamTimoutList;
/* Tcp stream hash table */
static __thread hashTablePtr tcpStreamHashTable;

/* Tcp stream cache */
static __thread tcpStreamPtr streamCache = NULL;

/* Tcp process purpose, for proto analysis or detect */
static __thread boolean doProtoDetect = False;

/* Tcp process callback function */
static __thread tcpProcessCB tcpProcessCallback;

static boolean
before (u_int seq1, u_int seq2) {
    int ret;

    ret = (int) (seq1 - seq2);
    if (ret < 0)
        return True;
    else
        return False;
}

static boolean
after (u_int seq1, u_int seq2) {
    int ret;

    ret = (int) (seq1 - seq2);
    if (ret > 0)
        return True;
    else
        return False;
}

static boolean
tuple4IsEqual (tuple4Ptr addr1, tuple4Ptr addr2) {
    if (addr1->saddr.s_addr == addr2->saddr.s_addr &&
        addr1->source == addr2->source &&
        addr1->daddr.s_addr == addr2->daddr.s_addr &&
        addr1->dest == addr2->dest)
        return True;

    return False;
}

static char *
getTcpBreakdownStateName (tcpBreakdownState state) {
    switch (state) {
        case TCP_BREAKDOWN_CONNECTED:
            return "TCP_CONNECTED";

        case TCP_BREAKDOWN_DATA_EXCHANGING:
            return "TCP_DATA_EXCHANGING";

        case TCP_BREAKDOWN_CLOSED:
            return "TCP_CLOSED";

        case TCP_BREAKDOWN_RESET_TYPE1:
            return "TCP_RESET_TYPE1";

        case TCP_BREAKDOWN_RESET_TYPE2:
            return "TCP_RESET_TYPE2";

        case TCP_BREAKDOWN_RESET_TYPE3:
            return "TCP_RESET_TYPE3";

        case TCP_BREAKDOWN_RESET_TYPE4:
            return "TCP_RESET_TYPE4";

        default:
            return "TCP_STATE_UNKNOWN";
    }
}

/**
 * @brief Add tcp stream to global tcp stream timeout list.
 *
 * @param stream -- tcp stream to add
 * @param tm -- tcp stream closing time
 */
static void
addTcpStreamToClosingTimeoutList (tcpStreamPtr stream, timeValPtr tm) {
    tcpStreamTimeoutPtr tst;

    /* If already added, return directly */
    if (stream->inClosingTimeout)
        return;

    tst = (tcpStreamTimeoutPtr) malloc (sizeof (tcpStreamTimeout));
    if (tst == NULL) {
        LOGE ("Alloc tcp timeout error: %s.\n", strerror (errno));
        return;
    }

    stream->inClosingTimeout = True;
    tst->stream = stream;
    tst->timeout = tm->tvSec + TCP_STREAM_CLOSING_TIMEOUT;
    listAddTail (&tst->node, &tcpStreamTimoutList);
}

/**
 * @brief Delete tcp stream from closing timeout list.
 *
 * @param stream -- tcp stream to Delete
 */
static void
delTcpStreamFromClosingTimeoutList (tcpStreamPtr stream) {
    tcpStreamTimeoutPtr entry;
    listHeadPtr pos, npos;

    if (!stream->inClosingTimeout)
        return;

    listForEachEntrySafe (entry, pos, npos, &tcpStreamTimoutList, node) {
        if (entry->stream == stream) {
            listDel (&entry->node);
            free (entry);
            return;
        }
    }
}

/**
 * @brief Lookup tcp stream from global tcp stream hash table.
 *
 * @param addr -- tcp stream 4 tuple address
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
lookupTcpStreamFromHash (tuple4Ptr addr) {
    char ipSrcStr [16], ipDestStr [16];
    char key [64];

    inet_ntop (AF_INET, (void *) &addr->saddr, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &addr->daddr, ipDestStr, sizeof (ipDestStr));

    snprintf (key, sizeof (key), TCP_STREAM_HASH_KEY_FORMAT,
              ipSrcStr, addr->source, ipDestStr, addr->dest);
    return (tcpStreamPtr) hashLookup (tcpStreamHashTable, key);
}

/**
 * @brief Add tcp stream to global hash table.
 *
 * @param stream -- tcp stream to add
 * @param freeFun -- tcp stream free function
 *
 * @return 0 if success else -1
 */
static int
addTcpStreamToHash (tcpStreamPtr stream, hashItemFreeCB freeFun) {
    int ret;
    tuple4Ptr addr;
    char ipSrcStr [16], ipDestStr [16];
    char key [64];

    addr = &stream->addr;
    inet_ntop (AF_INET, (void *) &addr->saddr, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &addr->daddr, ipDestStr, sizeof (ipDestStr));

    snprintf (key, sizeof (key), TCP_STREAM_HASH_KEY_FORMAT,
              ipSrcStr, addr->source, ipDestStr, addr->dest);
    ret = hashInsert (tcpStreamHashTable, key, stream, freeFun);
    if (ret < 0) {
        LOGE ("Insert stream to hash table error.\n");
        return -1;
    }

    if (!doProtoDetect)
        tcpStreamsAllocLocal++;

    return 0;
}

/**
 * @brief Remove tcp stream from hash table.
 *
 * @param stream -- tcp stream to remove
 */
static void
delTcpStreamFromHash (tcpStreamPtr stream, timeValPtr tm) {
    int ret;
    tuple4Ptr addr;
    char ipSrcStr [16], ipDestStr [16];
    char key [64];
    char *record;
    tcpProcessCallbackArgs callbackArgs;

    /* If streamCache will be deleted, reset streamCache */
    if (streamCache == stream)
        streamCache = NULL;

    addr = &stream->addr;
    inet_ntop (AF_INET, (void *) &addr->saddr, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &addr->daddr, ipDestStr, sizeof (ipDestStr));

    if (doProtoDetect) {
        if (stream->proto) {
            /* Add appService detected */
            if (getAppServiceDetected (ipDestStr, addr->dest) == NULL ||
                (getAppServiceFromBlacklist (ipDestStr, addr->dest) == NULL &&
                 getAppServiceProtoAnalyzer (ipDestStr, addr->dest) == NULL)) {
                ret = addAppServiceDetected (ipDestStr, addr->dest, stream->proto);
                if (ret < 0)
                    LOGE ("Add new detected appService ip:%s port:%u proto: %s error.\n",
                          ipDestStr, addr->dest, stream->proto);
                else {
                    record = appServiceAnalysisRecord (tm, stream->proto, ipDestStr, addr->dest);
                    if (record) {
                        callbackArgs.type = PUBLISH_APP_SERVICE;
                        callbackArgs.args = record;
                        (*tcpProcessCallback) (&callbackArgs);

                        free (record);
                    }
                    LOGI ("Add new detected appService ip:%s port:%u proto: %s success.\n",
                          ipDestStr, addr->dest, stream->proto);
                }
            }
        }
    }

    snprintf (key, sizeof (key), TCP_STREAM_HASH_KEY_FORMAT,
              ipSrcStr, addr->source, ipDestStr, addr->dest);
    ret = hashRemove (tcpStreamHashTable, key);
    if (ret < 0)
        LOGE ("Delete stream from hash table error.\n");
    else if (!doProtoDetect)
        tcpStreamsFreeLocal++;
}

/**
 * @brief Find tcp stream from global hash table.
 *
 * @param tcph -- tcp header
 * @param iph -- ip header
 * @param direction -- return stream direction
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
findTcpStream (tcphdrPtr tcph, iphdrPtr iph, streamDirection *direction) {
    tuple4 addr, revAddr;
    tcpStreamPtr stream;

    addr.saddr = iph->ipSrc;
    addr.source = ntohs (tcph->source);
    addr.daddr = iph->ipDest;
    addr.dest = ntohs (tcph->dest);

    revAddr.saddr = iph->ipDest;
    revAddr.source = ntohs (tcph->dest);
    revAddr.daddr = iph->ipSrc;
    revAddr.dest = ntohs (tcph->source);

    /* Check stream cache */
    if (streamCache) {
        if (tuple4IsEqual (&streamCache->addr, &addr)) {
            *direction = STREAM_FROM_CLIENT;
            return streamCache;
        }

        if (tuple4IsEqual (&streamCache->addr, &revAddr)) {
            *direction = STREAM_FROM_SERVER;
            return streamCache;
        }
    }

    stream = lookupTcpStreamFromHash (&addr);
    if (stream) {
        streamCache = stream;
        *direction = STREAM_FROM_CLIENT;
        return stream;
    }

    stream = lookupTcpStreamFromHash (&revAddr);
    if (stream) {
        streamCache = stream;
        *direction = STREAM_FROM_SERVER;
        return stream;
    }

    return NULL;
}

static tcpStreamPtr
newTcpStream (protoAnalyzerPtr analyzer) {
    tcpStreamPtr stream;

    stream = (tcpStreamPtr) malloc (sizeof (tcpStream));
    if (stream == NULL)
        return NULL;

    if (!doProtoDetect) {
        stream->proto = analyzer->proto;
        stream->analyzer = analyzer;
    } else {
        stream->proto = NULL;
        stream->analyzer = NULL;
    }

    /* Init 4-tuple address */
    stream->addr.saddr.s_addr = 0;
    stream->addr.source = 0;
    stream->addr.daddr.s_addr = 0;
    stream->addr.dest = 0;
    /* Generate connection id */
    uuid_generate (stream->connId);
    /* Set stream init state */
    stream->state = STREAM_INIT;

    /* Init client halfStream */
    stream->client.state = TCP_CONN_CLOSED;
    stream->client.rcvBuf = NULL;
    stream->client.bufSize = 0;
    stream->client.offset = 0;
    stream->client.count = 0;
    stream->client.countNew = 0;
    stream->client.seq = 0;
    stream->client.ackSeq = 0;
    stream->client.firstDataSeq = 0;
    stream->client.urgData = 0;
    stream->client.urgCount = 0;
    stream->client.urgCountNew = 0;
    stream->client.urgSeen = 0;
    stream->client.urgPtr = 0;
    stream->client.window = 0;
    stream->client.tsOn = False;
    stream->client.wscaleOn = False;
    stream->client.currTs = 0;
    stream->client.wscale = 0;
    stream->client.mss = 0;
    initListHead (&stream->client.head);
    stream->client.rmemAlloc = 0;
    /* Init client halfStream end */

    /* Init server halfStream */
    stream->server.state = TCP_CONN_CLOSED;
    stream->server.rcvBuf = NULL;
    stream->server.bufSize = 0;
    stream->server.offset = 0;
    stream->server.count = 0;
    stream->server.countNew = 0;
    stream->server.seq = 0;
    stream->server.ackSeq = 0;
    stream->server.firstDataSeq = 0;
    stream->server.urgData = 0;
    stream->server.urgCount = 0;
    stream->server.urgCountNew = 0;
    stream->server.urgSeen = 0;
    stream->server.urgPtr = 0;
    stream->server.window = 0;
    stream->server.tsOn = False;
    stream->server.wscaleOn = False;
    stream->server.currTs = 0;
    stream->server.wscale = 0;
    stream->server.mss = 0;
    initListHead (&stream->server.head);
    stream->server.rmemAlloc = 0;
    /* Init server halfStream end */

    /* Init tcp session detail */
    stream->synTime = 0;
    stream->retries = 0;
    stream->retriesTime = 0;
    stream->dupSynAcks = 0;
    stream->synAckTime = 0;
    stream->estbTime = 0;
    stream->mss = 0;
    stream->c2sBytes = 0;
    stream->s2cBytes = 0;
    stream->c2sPkts = 0;
    stream->s2cPkts = 0;
    stream->tinyPkts = 0;
    stream->pawsPkts = 0;
    stream->retransmittedPkts = 0;
    stream->outOfOrderPkts = 0;
    stream->zeroWindows = 0;
    stream->dupAcks = 0;

    if (!doProtoDetect) {
        stream->sessionDetail = (*stream->analyzer->newSessionDetail) ();
        if (stream->sessionDetail == NULL) {
            free (stream);
            return NULL;
        }
    } else
        stream->sessionDetail = NULL;
    stream->inClosingTimeout = False;
    stream->closeTime = 0;
    initListHead (&stream->node);

    return stream;
}

static void
freeTcpStream (tcpStreamPtr stream) {
    skbuffPtr entry;
    listHeadPtr pos, npos;

    /* Delete stream from global tcp stream list */
    listDel (&stream->node);
    /* Delete stream from closing timeout list */
    delTcpStreamFromClosingTimeoutList (stream);

    /* Free client halfStream */
    listForEachEntrySafe (entry, pos, npos, &stream->client.head, node) {
        listDel (&entry->node);
        free (entry->data);
        free (entry);
    }
    free (stream->client.rcvBuf);

    /* Free server halfStream */
    listForEachEntrySafe (entry, pos, npos, &stream->server.head, node) {
        listDel (&entry->node);
        free (entry->data);
        free (entry);
    }
    free (stream->server.rcvBuf);

    /* Free session detail */
    if (!doProtoDetect)
        (*stream->analyzer->freeSessionDetail) (stream->sessionDetail);

    free (stream);
}

static void
freeTcpStreamForHash (void *data) {
    tcpStreamPtr stream = (tcpStreamPtr) data;

    freeTcpStream (stream);
}

/**
 * @brief Alloc new tcp stream and add it to tcp stream hash table.
 *
 * @param tcph -- tcp header for current packet
 * @param iph -- ip header for current packet
 * @param tm -- timestamp for current packet
 *
 * @return Tcp stream if success else NULL
 */
static tcpStreamPtr
addNewTcpStream (tcphdrPtr tcph, iphdrPtr iph, timeValPtr tm) {
    int ret;
    char ipSrcStr [16], ipDestStr [16];
    char *record;
    protoAnalyzerPtr analyzer;
    tcpStreamPtr stream, tmp;
    tcpProcessCallbackArgs callbackArgs;

    inet_ntop (AF_INET, (void *) &iph->ipSrc, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &iph->ipDest, ipDestStr, sizeof (ipDestStr));

    if (doProtoDetect) {
        analyzer = NULL;

        /* Add topology entry */
        if (getTopologyEntry (ipSrcStr, ipDestStr) == NULL) {
            ret = addTopologyEntry (ipSrcStr, ipDestStr);
            if (ret < 0)
                LOGE ("Add topology entry %s:%s error.\n", ipSrcStr, ipDestStr);
            else {
                record = topologyEntryAnalysisRecord (tm, ipSrcStr, ipDestStr);
                if (record) {
                    callbackArgs.type = PUBLISH_TOPOLOGY_ENTRY;
                    callbackArgs.args = record;
                    (*tcpProcessCallback) (&callbackArgs);

                    free (record);
                }
                LOGI ("Add new topology entry %s:%s success.\n", ipSrcStr, ipDestStr);
            }
        }

        /* Skip service has been scanned */
        if (getAppServiceDetected (ipDestStr, ntohs (tcph->dest)) &&
            (getAppServiceProtoAnalyzer (ipDestStr, ntohs (tcph->dest)) ||
             getAppServiceFromBlacklist (ipDestStr, ntohs (tcph->dest))))
            return NULL;
    } else {
        analyzer = getAppServiceProtoAnalyzer (ipDestStr, ntohs (tcph->dest));
        if (analyzer == NULL)
            return NULL;
    }

    stream = newTcpStream (analyzer);
    if (stream == NULL) {
        LOGE ("Create new tcpStream error.\n");
        return NULL;
    }

    /* Set stream 4-tuple address */
    stream->addr.saddr = iph->ipSrc;
    stream->addr.source = ntohs (tcph->source);
    stream->addr.daddr = iph->ipDest;
    stream->addr.dest = ntohs (tcph->dest);

    /* Set client halfStream */
    stream->client.state = TCP_SYN_PKT_SENT;
    stream->client.seq = ntohl (tcph->seq) + 1;
    stream->client.firstDataSeq = stream->client.seq;
    stream->client.window = ntohs (tcph->window);
    stream->client.tsOn = getTimeStampOption (tcph, &stream->client.currTs);
    stream->client.wscaleOn = getTcpWindowScaleOption (tcph, &stream->client.wscale);
    if (!stream->client.wscaleOn)
        stream->client.wscale = 1;
    if (!getTcpMssOption (tcph, &stream->client.mss))
        LOGW ("Tcp MSS from client is null.\n");
    stream->synTime = timeVal2MilliSecond (tm);
    stream->retriesTime = timeVal2MilliSecond (tm);
    stream->c2sBytes = ntohs (iph->ipLen);
    stream->c2sPkts++;
    if (!stream->client.window)
        stream->zeroWindows++;

    /* Check the count of tcp streams. If the count of tcp streams exceed eighty
     * percent of tcpStreamHashTable limit size then remove the oldest tcp stream
     * from global tcp stream list.
     */
    if (hashSize (tcpStreamHashTable) >= (hashLimit (tcpStreamHashTable) * 0.8)) {
        tmp = listHeadEntry (&tcpStreamList, tcpStream, node);
        delTcpStreamFromHash (tmp, tm);
    }

    /* Add to global tcp stream list */
    listAddTail (&stream->node, &tcpStreamList);

    /* Add to global tcp stream hash table */
    ret = addTcpStreamToHash (stream, freeTcpStreamForHash);
    if (ret < 0) {
        LOGE ("Add tcp stream to stream hash table error.\n");
        return NULL;
    } else
        return stream;
}

static char *
tcpBreakdown2AnalysisRecord (tcpStreamPtr stream, tcpBreakdownPtr tbd) {
    char *out;
    json_t *root;
    char ipStr [16];
    char buf [64];

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create js2on object error.\n");
        return NULL;
    }
    /* Analysis record timestamp */
    formatLocalTimeStr (&tbd->timestamp, buf, sizeof (buf));
    json_object_set_new (root, ANALYSIS_RECORD_TIMESTAMP,
                         json_string (buf));

    /* Analysis record type */
    json_object_set_new (root, ANALYSIS_RECORD_TYPE,
                         json_string (ANALYSIS_RECORD_TYPE_TCP_BREAKDOWN));

    /* Tcp application level proto type */
    json_object_set_new (root, TCP_BKD_PROTO,
                         json_string (tbd->proto));

    /* Tcp source ip */
    inet_ntop (AF_INET, (void *) &tbd->ipSrc, ipStr, sizeof (ipStr));
    json_object_set_new (root, TCP_BKD_SOURCE_IP,
                         json_string (ipStr));

    /* Tcp source port */
    json_object_set_new (root, TCP_BKD_SOURCE_PORT,
                         json_integer (tbd->source));

    /* Tcp service ip */
    inet_ntop (AF_INET, (void *) &tbd->svcIp, ipStr, sizeof (ipStr));
    json_object_set_new (root, TCP_BKD_SERVICE_IP,
                         json_string (ipStr));

    /* Tcp service port */
    json_object_set_new (root, TCP_BKD_SERVICE_PORT,
                         json_integer (tbd->svcPort));

    /* Tcp connection id */
    uuid_unparse (tbd->connId, buf);
    json_object_set_new (root, TCP_BKD_TCP_CONNECTION_ID,
                         json_string (buf));

    /* Tcp state */
    json_object_set_new (root, TCP_BKD_TCP_STATE,
                         json_string (getTcpBreakdownStateName (tbd->state)));

    /* Tcp retries */
    json_object_set_new (root, TCP_BKD_TCP_RETRIES,
                         json_integer (tbd->retries));

    /* Tcp retries latency */
    json_object_set_new (root, TCP_BKD_TCP_RETRIES_LATENCY,
                         json_integer (tbd->retriesLatency));

    /* Tcp duplicate syn/ack packets */
    json_object_set_new (root, TCP_BKD_TCP_DUPLICATE_SYNACKS,
                         json_integer (tbd->dupSynAcks));

    /* Tcp RTT */
    json_object_set_new (root, TCP_BKD_TCP_RTT,
                         json_integer (tbd->rtt));

    /* Tcp MSS */
    json_object_set_new (root, TCP_BKD_TCP_MSS,
                         json_integer (tbd->mss));

    /* Tcp connection latency */
    json_object_set_new (root, TCP_BKD_TCP_CONNECTION_LATENCY,
                         json_integer (tbd->connLatency));

    /* Tcp c2s bytes */
    json_object_set_new (root, TCP_BKD_TCP_C2S_BYTES,
                         json_integer (tbd->c2sBytes));

    /* Tcp s2c bytes */
    json_object_set_new (root, TCP_BKD_TCP_S2C_BYTES,
                         json_integer (tbd->s2cBytes));

    /* Tcp total bytes */
    json_object_set_new (root, TCP_BKD_TCP_TOTAL_BYTES,
                         json_integer (tbd->totalBytes));

    /* Tcp c2s packets */
    json_object_set_new (root, TCP_BKD_TCP_C2S_PACKETS,
                         json_integer (tbd->c2sPkts));

    /* Tcp s2c packets */
    json_object_set_new (root, TCP_BKD_TCP_S2C_PACKETS,
                         json_integer (tbd->s2cPkts));

    /* Tcp total packets */
    json_object_set_new (root, TCP_BKD_TCP_TOTAL_PACKETS,
                         json_integer (tbd->totalPkts));

    /* Tcp tiny packets */
    json_object_set_new (root, TCP_BKD_TCP_TINY_PACKETS,
                         json_integer (tbd->tinyPkts));

    /* Tcp PAWS packets */
    json_object_set_new (root, TCP_BKD_TCP_PAWS_PACKETS,
                         json_integer (tbd->pawsPkts));

    /* Tcp retransmitted packets */
    json_object_set_new (root, TCP_BKD_TCP_RETRANSMITTED_PACKETS,
                         json_integer (tbd->retransmittedPkts));

    /* Tcp out of order packets */
    json_object_set_new (root, TCP_BKD_TCP_OUT_OF_ORDER_PACKETS,
                         json_integer (tbd->outOfOrderPkts));

    /* Tcp zero windows */
    json_object_set_new (root, TCP_BKD_TCP_ZERO_WINDOWS,
                         json_integer (tbd->zeroWindows));

    /* Tcp duplicate acks */
    json_object_set_new (root, TCP_BKD_TCP_DUPLICATE_ACKS,
                         json_integer (tbd->dupAcks));

    if (tbd->state == TCP_BREAKDOWN_DATA_EXCHANGING ||
        tbd->state == TCP_BREAKDOWN_RESET_TYPE3 ||
        tbd->state == TCP_BREAKDOWN_RESET_TYPE4)
        (*stream->analyzer->sessionBreakdown2Json) (root, stream->sessionDetail,
                                                    tbd->sessionBreakdown);

    out = json_dumps (root, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_object_clear (root);

    return out;
}

static void
generateTcpBreakdown (tcpStreamPtr stream, timeValPtr tm) {
    int ret;
    tcpBreakdown tbd;
    char *record = NULL;
    tcpProcessCallbackArgs callbackArgs;

    tbd.sessionBreakdown = (*stream->analyzer->newSessionBreakdown) ();
    if (tbd.sessionBreakdown == NULL) {
        LOGE ("Create new sessionBreakdown error.\n");
        return;
    }

    tbd.timestamp.tvSec = tm->tvSec;
    tbd.timestamp.tvUsec = tm->tvUsec;
    tbd.proto = stream->proto;
    tbd.ipSrc = stream->addr.saddr;
    tbd.source = stream->addr.source;
    tbd.svcIp = stream->addr.daddr;
    tbd.svcPort = stream->addr.dest;
    uuid_copy (tbd.connId, stream->connId);

    switch (stream->state) {
        case STREAM_CONNECTED:
            tbd.state = TCP_BREAKDOWN_CONNECTED;
            break;

        case STREAM_DATA_EXCHANGING:
        case STREAM_CLOSING:
            tbd.state = TCP_BREAKDOWN_DATA_EXCHANGING;
            break;

        case STREAM_TIME_OUT:
        case STREAM_CLOSED:
            tbd.state = TCP_BREAKDOWN_CLOSED;
            break;

        case STREAM_RESET_TYPE1:
            tbd.state = TCP_BREAKDOWN_RESET_TYPE1;
            break;

        case STREAM_RESET_TYPE2:
            tbd.state = TCP_BREAKDOWN_RESET_TYPE2;
            break;

        case STREAM_RESET_TYPE3:
            tbd.state = TCP_BREAKDOWN_RESET_TYPE3;
            break;

        case STREAM_RESET_TYPE4:
            tbd.state = TCP_BREAKDOWN_RESET_TYPE4;
            break;

        default:
            (*stream->analyzer->freeSessionBreakdown) (tbd.sessionBreakdown);
            LOGE ("Unknown stream state for breakdown.\n");
            return;
    }

    switch (tbd.state) {
        case TCP_BREAKDOWN_CONNECTED:
            tbd.retries = stream->retries;
            tbd.retriesLatency = stream->retriesTime - stream->synTime;
            tbd.dupSynAcks = stream->dupSynAcks;
            tbd.connLatency = stream->estbTime - stream->retriesTime;
            break;

        default:
            tbd.retries = 0;
            tbd.retriesLatency = 0;
            tbd.dupSynAcks = 0;
            tbd.connLatency = 0;
            break;
    }

    tbd.rtt = stream->estbTime - stream->retriesTime;
    tbd.mss = stream->mss;
    tbd.c2sBytes = stream->c2sBytes;
    tbd.s2cBytes = stream->s2cBytes;
    tbd.totalBytes = stream->c2sBytes + stream->s2cBytes;
    tbd.c2sPkts = stream->c2sPkts;
    tbd.s2cPkts = stream->s2cPkts;
    tbd.totalPkts = stream->c2sPkts + stream->s2cPkts;
    tbd.tinyPkts = stream->tinyPkts;
    tbd.pawsPkts = stream->pawsPkts;
    tbd.retransmittedPkts = stream->retransmittedPkts;
    tbd.outOfOrderPkts = stream->outOfOrderPkts;
    tbd.zeroWindows = stream->zeroWindows;
    tbd.dupAcks = stream->dupAcks;

    /* For TCP_BREAKDOWN_DATA_EXCHANGING, TCP_BREAKDOWN_RESET_TYPE3 and
     * TCP_BREAKDOWN_RESET_TYPE4 breakdown, there is application layer
     * breakdown */
    if (tbd.state == TCP_BREAKDOWN_DATA_EXCHANGING ||
        tbd.state == TCP_BREAKDOWN_RESET_TYPE3 ||
        tbd.state == TCP_BREAKDOWN_RESET_TYPE4) {
        ret = (*stream->analyzer->generateSessionBreakdown) (stream->sessionDetail,
                                                             tbd.sessionBreakdown);
        if (ret < 0) {
            LOGE ("GenerateSessionBreakdown error.\n");
            (*stream->analyzer->freeSessionBreakdown) (tbd.sessionBreakdown);
            return;
        }
    }

    record = tcpBreakdown2AnalysisRecord (stream, &tbd);
    if (record == NULL) {
        LOGE ("SessionBreakdown2Json error.\n");
        (*stream->analyzer->freeSessionBreakdown) (tbd.sessionBreakdown);
        return;
    }

    callbackArgs.type = PUBLISH_TCP_BREAKDOWN;
    callbackArgs.args = record;
    (*tcpProcessCallback) (&callbackArgs);

    /* Free record string and application layer session breakdown */
    free (record);
    (*stream->analyzer->freeSessionBreakdown) (tbd.sessionBreakdown);

    /* Reset some statistic fields of tcp stream */
    stream->c2sBytes = 0;
    stream->s2cBytes = 0;
    stream->c2sPkts = 0;
    stream->s2cPkts = 0;
    stream->tinyPkts = 0;
    stream->pawsPkts = 0;
    stream->retransmittedPkts = 0;
    stream->outOfOrderPkts = 0;
    stream->zeroWindows = 0;
    stream->dupAcks = 0;
}

/**
 * @brief Check tcp stream timeout list and remove timeout
 *        tcp stream.
 *
 * @param tm -- timestamp for current packet
 */
static void
checkTcpStreamClosingTimeoutList (timeValPtr tm) {
    tcpStreamTimeoutPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &tcpStreamTimoutList, node) {
        if (entry->timeout > tm->tvSec)
            return;

        entry->stream->state = STREAM_TIME_OUT;
        entry->stream->closeTime = timeVal2MilliSecond (tm);
        if (!doProtoDetect)
            generateTcpBreakdown (entry->stream, tm);
        delTcpStreamFromHash (entry->stream, tm);
    }
}

/* Tcp connection establishment handler callback */
static void
handleEstb (tcpStreamPtr stream, timeValPtr tm) {
    /* Set tcp state */
    stream->client.state = TCP_CONN_ESTABLISHED;
    stream->server.state = TCP_CONN_ESTABLISHED;
    stream->state = STREAM_CONNECTED;
    stream->estbTime = timeVal2MilliSecond (tm);
    stream->mss = MIN_NUM (stream->client.mss, stream->server.mss);

    if (!doProtoDetect) {
        (*stream->analyzer->sessionProcessEstb) (tm, stream->sessionDetail);
        generateTcpBreakdown (stream, tm);
    }
}

/* Tcp urgency data handler callback */
static void
handleUrgData (tcpStreamPtr stream, halfStreamPtr snd,
               u_char urgData, timeValPtr tm) {
    streamDirection direction;

    if (snd == &stream->client)
        direction = STREAM_FROM_CLIENT;
    else
        direction = STREAM_FROM_SERVER;

    if (!doProtoDetect)
        (*stream->analyzer->sessionProcessUrgData) (direction, urgData,
                                                    tm, stream->sessionDetail);
}

/* Tcp data handler callback */
static u_int
handleData (tcpStreamPtr stream, halfStreamPtr snd,
            u_char *data, u_int dataLen, timeValPtr tm) {
    streamDirection direction;
    u_int parseCount;
    sessionState state = SESSION_ACTIVE;

    if (snd == &stream->client)
        direction = STREAM_FROM_CLIENT;
    else
        direction = STREAM_FROM_SERVER;

    if (!doProtoDetect) {
        parseCount = (*stream->analyzer->sessionProcessData) (direction, data, dataLen,
                                                              tm, stream->sessionDetail, &state);
        if (state == SESSION_DONE)
            generateTcpBreakdown (stream, tm);
    } else {
        if (stream->proto == NULL)
            stream->proto = protoDetect (direction, tm, data, dataLen);

        parseCount = dataLen;
    }

    return parseCount;
}

/* Tcp reset handler callback */
static void
handleReset (tcpStreamPtr stream, halfStreamPtr snd, timeValPtr tm) {
    streamDirection direction;

    if (snd == &stream->client)
        direction = STREAM_FROM_CLIENT;
    else
        direction = STREAM_FROM_SERVER;

    if (stream->state == STREAM_INIT) {
        if (direction == STREAM_FROM_CLIENT)
            stream->state = STREAM_RESET_TYPE1;
        else
            stream->state = STREAM_RESET_TYPE2;
    } else {
        if (direction == STREAM_FROM_CLIENT)
            stream->state = STREAM_RESET_TYPE3;
        else
            stream->state = STREAM_RESET_TYPE4;

        if (!doProtoDetect)
            (*stream->analyzer->sessionProcessReset) (direction, tm,
                                                      stream->sessionDetail);
    }

    stream->closeTime = timeVal2MilliSecond (tm);
    if (!doProtoDetect)
        generateTcpBreakdown (stream, tm);
    delTcpStreamFromHash (stream, tm);
}

/* Tcp fin handler callback */
static void
handleFin (tcpStreamPtr stream, halfStreamPtr snd, timeValPtr tm) {
    streamDirection direction;
    sessionState state = SESSION_ACTIVE;

    if (snd == &stream->client)
        direction = STREAM_FROM_CLIENT;
    else
        direction = STREAM_FROM_SERVER;

    if (!doProtoDetect) {
        (*stream->analyzer->sessionProcessFin) (direction, tm,
                                                stream->sessionDetail, &state);
        if (state == SESSION_DONE)
            generateTcpBreakdown (stream, tm);
    }

    snd->state = TCP_FIN_PKT_SENT;
    stream->state = STREAM_CLOSING;
    addTcpStreamToClosingTimeoutList (stream, tm);
}

/* Tcp close handler callback */
static void
handleClose (tcpStreamPtr stream, timeValPtr tm) {
    stream->state = STREAM_CLOSED;
    stream->closeTime = timeVal2MilliSecond (tm);
    if (!doProtoDetect)
        generateTcpBreakdown (stream, tm);
    delTcpStreamFromHash (stream, tm);
}

/**
 * @brief Add data to halfStream receive buffer.
 *
 * @param rcv -- halfStream to receive
 * @param data -- data to add
 * @param dataLen -- data length to add
 *
 * @return 0 if success else -1
 */
static int
addToBuf (halfStreamPtr rcv, u_char *data, u_int dataLen) {
    int ret = 0;
    u_int toAlloc;
    u_char *tmp;

    if ((rcv->count - rcv->offset + dataLen) > rcv->bufSize) {
        if (rcv->rcvBuf == NULL) {
            if (dataLen < 2048)
                toAlloc = 4096;
            else
                toAlloc = dataLen * 2;

            rcv->rcvBuf = (u_char *) malloc (toAlloc);
            if (rcv->rcvBuf == NULL) {
                LOGE ("Alloc memory for halfStream rcvBuf error: %s.\n",
                      strerror (errno));
                ret = -1;
            }
        } else {
            /*
             * If receive buffer size exceed TCP_RECEIVE_BUFFER_MAX_SIZE then
             * free it in case exhausting too much memory.
             */
            if (rcv->bufSize >= TCP_RECEIVE_BUFFER_MAX_SIZE) {
                LOGW ("Exceed maxium tcp stream receive buffer size.\n");
                free (rcv->rcvBuf);
                rcv->rcvBuf = NULL;
                ret = -1;
            } else {
                if (dataLen < rcv->bufSize)
                    toAlloc = rcv->bufSize * 2;
                else
                    toAlloc = rcv->bufSize + dataLen * 2;

                tmp = (u_char *) realloc (rcv->rcvBuf, toAlloc);
                if (tmp == NULL) {
                    LOGE ("Realloc memory for halfStream rcvBuf error: %s.\n",
                          strerror (errno));
                    free (rcv->rcvBuf);
                    rcv->rcvBuf = NULL;
                    ret = -1;
                } else
                    rcv->rcvBuf = tmp;
            }
        }

        if (ret < 0)
            rcv->bufSize = 0;
        else
            rcv->bufSize = toAlloc;
    }

    if (!ret)
        memcpy (rcv->rcvBuf + rcv->count - rcv->offset, data, dataLen);
    rcv->count += dataLen;
    rcv->countNew = dataLen;
    return ret;
}

/**
 * @brief Tcp data defragment, merge data from skbuff to receiver's receive
 *        buffer. If data contains urgData, it needs to update receiver's urg
 *        data and pointer first else merge data directly.
 *
 * @param stream -- current tcp stream
 * @param snd -- tcp sender
 * @param rcv -- tcp receiver
 * @param data -- data to merge
 * @param dataLen -- data length
 * @param curSeq -- current send sequence
 * @param fin -- fin flag
 * @param urg -- urg flag
 * @param urgPtr -- urgPointer
 * @param push -- push flag
 * @param tm -- current timestamp
 */
static void
addFromSkb (tcpStreamPtr stream,
            halfStreamPtr snd, halfStreamPtr rcv,
            u_char *data, u_int dataLen, u_int curSeq,
            u_char fin, u_char urg, u_short urgPtr, u_char push, timeValPtr tm) {
    int ret;
    u_int parseCount;
    u_int toCopy1, toCopy2;
    u_int lost = EXP_SEQ - curSeq;

    if (urg &&
        !before (urgPtr, EXP_SEQ) &&
        (!rcv->urgSeen || after (urgPtr, rcv->urgPtr))) {
        rcv->urgPtr = urgPtr;
        rcv->urgSeen = 1;
    }

    if (rcv->urgSeen &&
        !before (rcv->urgPtr, EXP_SEQ) &&
        before (rcv->urgPtr, curSeq + dataLen)) {
        /* Hanlde data before urgData */
        toCopy1 = rcv->urgPtr - EXP_SEQ;
        if (toCopy1 > 0) {
            ret = addToBuf (rcv, data + lost, toCopy1);
            if (ret < 0) {
                LOGE ("Add data to receive buffer error.\n");
                rcv->offset = rcv->count;
            } else {
                parseCount = handleData (stream, snd, rcv->rcvBuf,
                                         rcv->count - rcv->offset, tm);
                rcv->offset += parseCount;
                if (parseCount)
                    memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,
                             rcv->count - rcv->offset);
            }
            rcv->countNew = 0;
        }

        /* Handle urgData */
        rcv->urgData = data [rcv->urgPtr - curSeq];
        rcv->urgCountNew = 1;
        handleUrgData (stream, snd, rcv->urgData, tm);
        rcv->urgCountNew = 0;
        rcv->urgSeen = 0;
        rcv->urgCount++;

        /* Handle data after urgData */
        toCopy2 = curSeq + dataLen - rcv->urgPtr - 1;
        if (toCopy2 > 0) {
            ret = addToBuf (rcv, data + lost + toCopy1 + 1, toCopy2);
            if (ret < 0) {
                LOGE ("Add data to receive buffer error.\n");
                rcv->offset = rcv->count;
            } else {
                parseCount = handleData (stream, snd, rcv->rcvBuf,
                                         rcv->count - rcv->offset, tm);
                rcv->offset += parseCount;
                if (parseCount)
                    memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,
                             rcv->count - rcv->offset);
            }
            rcv->countNew = 0;
        }
    } else {
        if (dataLen - lost > 0) {
            ret = addToBuf (rcv, data + lost, dataLen - lost);
            if (ret < 0) {
                LOGE ("Add data to receive buffer error.\n");
                rcv->offset = rcv->count;
            } else {
                parseCount = handleData (stream, snd, rcv->rcvBuf,
                                         rcv->count - rcv->offset, tm);
                rcv->offset += parseCount;
                if (parseCount)
                    memmove (rcv->rcvBuf, rcv->rcvBuf + parseCount,
                             rcv->count - rcv->offset);
            }
            rcv->countNew = 0;
        }
    }

    if (fin)
        handleFin (stream, snd, tm);
}

/**
 * @brief Tcp queue process, for expected data merge it to receiver's
 *        receive buffer directly else store it to skbuff and link it
 *        to receiver's skbuff list.
 *
 * @param stream -- current tcp stream
 * @param tcph -- tcp header
 * @param snd -- tcp sender
 * @param rcv -- tcp receiver
 * @param data -- data to merge
 * @param dataLen -- data length
 * @param tm -- current timestamp
 */
static void
tcpQueue (tcpStreamPtr stream,
          tcphdrPtr tcph,
          halfStreamPtr snd, halfStreamPtr rcv,
          u_char *data, u_int dataLen, timeValPtr tm) {
    u_int curSeq;
    skbuffPtr skbuf, entry;
    listHeadPtr pos, ppos, npos;

    curSeq = ntohl (tcph->seq);
    if (!after (curSeq, EXP_SEQ)) {
        /* Accumulate out of order packets */
        if (before (curSeq, EXP_SEQ))
            stream->retransmittedPkts++;

        if (after (curSeq + dataLen + tcph->fin, EXP_SEQ)) {
            /* The packet straddles our window end */
            if (snd->tsOn)
                getTimeStampOption (tcph, &snd->currTs);

            addFromSkb (stream, snd, rcv,
                        (u_char *) data, dataLen, curSeq,
                        tcph->fin, tcph->urg, curSeq + ntohs (tcph->urgPtr) - 1,
                        tcph->psh, tm);

            listForEachEntrySafe (entry, pos, npos, &rcv->head, node) {
                if (after (entry->seq, EXP_SEQ))
                    break;
                listDel (&entry->node);
                if (after (entry->seq + entry->len + entry->fin, EXP_SEQ)) {
                    addFromSkb (stream, snd, rcv,
                                entry->data, entry->len, entry->seq,
                                entry->fin, entry->urg, entry->seq + entry->urgPtr - 1,
                                entry->psh, tm);
                }
                rcv->rmemAlloc -= entry->len;
                free (entry->data);
                free (entry);
            }
        } else
            return;
    } else {
        /* Accumulate out of order packets */
        stream->outOfOrderPkts++;

        /* Alloc new skbuff */
        skbuf = (skbuffPtr) malloc (sizeof (skbuff));
        if (skbuf == NULL) {
            LOGE ("Alloc memory for skbuff error: %s.\n", strerror (errno));
            return;
        }
        memset (skbuf, 0, sizeof (skbuff));
        skbuf->data = (u_char *) malloc (dataLen);
        if (skbuf->data == NULL) {
            LOGE ("Alloc memory for skbuff data error: %s.\n", strerror (errno));
            free (skbuf);
            return;
        }
        skbuf->len = dataLen;
        memcpy (skbuf->data, data, dataLen);
        skbuf->fin = tcph->fin;
        skbuf->seq = curSeq;
        skbuf->urg = tcph->urg;
        skbuf->urgPtr = ntohs (tcph->urgPtr);
        skbuf->psh = tcph->psh;

        if (skbuf->fin) {
            snd->state = TCP_CONN_CLOSING;
            addTcpStreamToClosingTimeoutList (stream, tm);
        }
        rcv->rmemAlloc += skbuf->len;

        listForEachEntryReverseSafe (entry, pos, ppos, &rcv->head, node) {
            if (before (entry->seq, curSeq)) {
                listAdd (&skbuf->node, &entry->node);
                return;
            }
        }
        listAdd (&skbuf->node, &rcv->head);
    }
}

/**
 * @brief Tcp packet processor.
 *        Tcp packet process function, it will defragment tcp packet
 *        and do tcp and application level performance analysis by
 *        calling specified proto analyzer to parse.
 *
 * @param iph -- ip packet header
 * @param tm -- packet capture timestamp
 */
void
tcpProcess (iphdrPtr iph, timeValPtr tm) {
    u_int ipLen;
    tcphdrPtr tcph;
    u_int tcpLen;
    u_char *tcpData;
    u_int tcpDataLen;
    u_int tmOption;
    timeVal timestamp;
    tcpStreamPtr stream;
    halfStreamPtr snd, rcv;
    streamDirection direction;

    ipLen = ntohs (iph->ipLen);
    tcph = (tcphdrPtr) ((u_char *) iph + iph->iphLen * 4);
    tcpLen = ipLen - iph->iphLen * 4;
    tcpData = (u_char *) tcph + tcph->doff * 4;
    tcpDataLen = ipLen - (iph->iphLen * 4) - (tcph->doff * 4);

    timestamp.tvSec = ntohll (tm->tvSec);
    timestamp.tvUsec = ntohll (tm->tvUsec);

    /* Tcp stream closing timout check */
    checkTcpStreamClosingTimeoutList (&timestamp);

    if (ipLen < (iph->iphLen * 4 + sizeof (tcphdr))) {
        LOGE ("Invalid tcp packet.\n");
        return;
    }

    if (tcpDataLen < 0) {
        LOGE ("Invalid tcp data length, ipLen: %u, tcpLen: %u, "
              "tcpHeaderLen: %u, tcpDataLen: %u.\n",
              ipLen, tcpLen, (tcph->doff * 4), tcpDataLen);
        return;
    }

    if (iph->ipSrc.s_addr == 0 || iph->ipDest.s_addr == 0) {
        LOGE ("Invalid ip address.\n");
        return;
    }

#ifdef DO_STRICT_CHECK
    /* Tcp checksum validation */
    if (tcpFastCheckSum ((u_char *) tcph, tcpLen,
                         iph->ipSrc.s_addr, iph->ipDest.s_addr)) {
        LOGE ("Tcp fast checksum error, ipLen: %u, tcpLen: %u, "
              "tcpHeaderLen: %u, tcpDataLen: %u.\n",
              ipLen, tcpLen, (tcph->doff * 4), tcpDataLen);
        return;
    }
#endif

    stream = findTcpStream (tcph, iph, &direction);
    if (stream == NULL) {
        /* The first sync packet of tcp three handshakes */
        if (tcph->syn && !tcph->ack && !tcph->rst) {
            stream = addNewTcpStream (tcph, iph, &timestamp);
            if (stream)
                streamCache = stream;
        }

        return;
    }

    /* For proto detection, if proto has been detected or get enough
     * packets then close stream in advance. */
    if (doProtoDetect &&
        (stream->proto ||
         (stream->proto == NULL &&
          stream->c2sPkts >= 20 &&
          stream->s2cPkts >= 20))) {
        stream->state = STREAM_CLOSED;
        stream->closeTime = timeVal2MilliSecond (tm);
        delTcpStreamFromHash (stream, &timestamp);

        return;
    }

    if (direction == STREAM_FROM_CLIENT) {
        snd = &stream->client;
        rcv = &stream->server;

        stream->c2sBytes += ntohs (iph->ipLen);
        stream->c2sPkts++;
    } else {
        rcv = &stream->client;
        snd = &stream->server;

        stream->s2cBytes += ntohs (iph->ipLen);
        stream->s2cPkts++;
    }

    /* Tcp window check */
    snd->window = ntohs (tcph->window);
    if (!snd->window)
        stream->zeroWindows++;

    if (tcph->syn) {
        if (direction == STREAM_FROM_CLIENT ||
            stream->client.state != TCP_SYN_PKT_SENT ||
            stream->server.state != TCP_CONN_CLOSED ||
            !tcph->ack) {
            /* Tcp syn retries */
            if (direction == STREAM_FROM_CLIENT &&
                stream->client.state == TCP_SYN_PKT_SENT) {
                stream->retries++;
                stream->retriesTime = timeVal2MilliSecond (&timestamp);
            } else if (direction == STREAM_FROM_SERVER &&
                       stream->server.state == TCP_SYN_PKT_RECV) {
                /* Tcp syn/ack retries */
                stream->dupSynAcks++;
                stream->synAckTime = timeVal2MilliSecond (&timestamp);
                stream->dupAcks++;
            }

            stream->retransmittedPkts++;
            return;
        } else {
            /* The second packet of tcp three handshakes */
            if (stream->client.seq != ntohl (tcph->ackSeq)) {
                LOGW ("Wrong ack sequence number of syn/ack packet.\n");
                return;
            }

            stream->server.state = TCP_SYN_PKT_RECV;
            stream->server.seq = ntohl (tcph->seq) + 1;
            stream->server.firstDataSeq = stream->server.seq;
            stream->server.ackSeq = ntohl (tcph->ackSeq);

            if (stream->client.tsOn) {
                stream->server.tsOn =
                        getTimeStampOption (tcph, &stream->server.currTs);
                if (!stream->server.tsOn)
                    stream->client.tsOn = False;
            } else
                stream->server.tsOn = False;

            if (stream->client.wscaleOn) {
                stream->server.wscaleOn =
                        getTcpWindowScaleOption (tcph, &stream->server.wscale);
                if (!stream->server.wscaleOn) {
                    stream->client.wscaleOn = False;
                    stream->client.wscale  = 1;
                    stream->server.wscale = 1;
                }
            } else {
                stream->server.wscaleOn = False;
                stream->server.wscale = 1;
            }

            if (!getTcpMssOption (tcph, &stream->server.mss))
                LOGW ("Tcp MSS from server is null.\n");

            stream->synAckTime = timeVal2MilliSecond (&timestamp);
        }

        return;
    }

    if (tcph->rst) {
        handleReset (stream, snd, &timestamp);
        return;
    }

    /* Filter retransmitted or out of window range packet */
    if (!(!tcpDataLen && ntohl (tcph->seq) == rcv->ackSeq) &&
        (before (ntohl (tcph->seq) + tcpDataLen, rcv->ackSeq) ||
         !before (ntohl (tcph->seq), (rcv->ackSeq + rcv->window * rcv->wscale)))) {
        /* Accumulate retransmitted packets */
        if (before (ntohl (tcph->seq) + tcpDataLen, rcv->ackSeq))
            stream->retransmittedPkts++;
        return;
    }

    /* PAWS (Protect Against Wrapped Sequence numbers) check */
    if (rcv->tsOn &&
        getTimeStampOption (tcph, &tmOption) &&
        before (tmOption, snd->currTs)) {
        stream->pawsPkts++;
        return;
    }

    if (tcph->ack) {
        if (direction == STREAM_FROM_CLIENT &&
            stream->client.state == TCP_SYN_PKT_SENT &&
            stream->server.state == TCP_SYN_PKT_RECV) {
            /* The last packet of tcp three handshakes */
            if (ntohl (tcph->ackSeq) == stream->server.seq) {
                handleEstb (stream, &timestamp);
                stream->state = STREAM_DATA_EXCHANGING;
            } else
                stream->outOfOrderPkts++;
        }

        /* Update ackSeq */
        if (ntohl (tcph->ackSeq) > snd->ackSeq)
            snd->ackSeq = ntohl (tcph->ackSeq);
        else if (!tcpDataLen) {
            /* For out of order packets, if receiver doesn't receive all packets, it
             * will send a single ack packet to ackownledge the last received successive
             * packet, in that case, client will resend the dropped packet again */
            stream->dupAcks++;
        }

        if (rcv->state == TCP_FIN_PKT_SENT)
            rcv->state = TCP_FIN_PKT_CONFIRMED;

        if (rcv->state == TCP_FIN_PKT_CONFIRMED &&
            snd->state == TCP_FIN_PKT_CONFIRMED) {
            handleClose (stream, &timestamp);
            return;
        }
    }

    if (tcpDataLen + tcph->fin > 0) {
        if (tcpDataLen == 1)
            stream->tinyPkts++;
        tcpQueue (stream, tcph, snd, rcv, tcpData, tcpDataLen, &timestamp);
    }
}

static void
dispalyLocalStatisticInfo (void) {
    LOGI ("\n"
          "==Local tcp packet statistic info==\n"
          "--tcpStreamsAlloc: %u\n"
          "--tcpStreamsFree: %u\n\n",
          tcpStreamsAllocLocal, tcpStreamsFreeLocal);
}

/* Reset tcp context */
int
resetTcpContext (void) {
    hashClean (tcpStreamHashTable);

    streamCache = NULL;

    return 0;
}

/* Init tcp context */
int
initTcpContext (boolean protoDetectFlag, tcpProcessCB fun) {
    doProtoDetect = protoDetectFlag;
    tcpProcessCallback = fun;

    initListHead (&tcpStreamList);
    initListHead (&tcpStreamTimoutList);

    if (doProtoDetect)
        tcpStreamHashTable = hashNew (TCP_STREAM_HASH_TABLE_SIZE_FOR_PROTO_DETECT);
    else
        tcpStreamHashTable = hashNew (TCP_STREAM_HASH_TABLE_SIZE);

    if (tcpStreamHashTable == NULL)
        return -1;

    streamCache = NULL;

    return 0;
}

/* Destroy tcp context */
void
destroyTcpContext (void) {
    if (!doProtoDetect)
        dispalyLocalStatisticInfo ();

    hashDestroy (tcpStreamHashTable);
    tcpStreamHashTable = NULL;
}
