#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "config.h"
#include "util.h"
#include "list.h"
#include "hash.h"
#include "checksum.h"
#include "log.h"
#include "app_service_manager.h"
#include "ip.h"
#include "tcp.h"
#include "ip_options.h"
#include "ip_packet.h"

/* Ip packet maximum size */
#define MAX_IP_PACKET_SIZE 65535
/* Default expire timeout of ipQueue */
#define DEFAULT_IPQUEUE_EXPIRE_TIMEOUT 30
/* Default ipQueue hash table size */
#define DEFAULT_IPQUEUE_HASH_TABLE_SIZE 65535
/* ipQueue hash key format string */
#define IPQUEUE_HASH_KEY_FORMAT "%s:%s:%u"

/* IpQueue expire timeout list */
static __thread listHead ipQueueExpireTimeoutList;

/* Ip host fragment hash table */
static __thread hashTablePtr ipQueueHashTable = NULL;

/* Ip process purpose, for proto analysis or detect */
static __thread boolean doProtoDetect = False;

static void
displayIphdr (iphdrPtr iph) {
    u_short offset, flags;
    char ipSrcStr [16], ipDestStr [16];

    offset = ntohs (iph->ipOff);
    flags = offset & ~IP_OFFMASK;
    offset = (offset & IP_OFFMASK) << 3;

    if (flags & IP_MF || offset)
        LOGD ("Fragment ip packet");
    else
        LOGD ("Defragment ip packet");

    inet_ntop (AF_INET, (void *) &iph->ipSrc, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &iph->ipDest, ipDestStr, sizeof (ipDestStr));
    LOGD (" src: %s ------------> dst: %s\n", ipSrcStr, ipDestStr);
    LOGD ("Ip header len: %d , ip packet len: %u, offset: %u, IP_MF: %u.\n",
          (iph->iphLen * 4), ntohs (iph->ipLen), offset, ((flags & IP_MF) ? 1 : 0));
}

/* Check ip packet to drop */
static boolean
ipPktShouldDrop (iphdrPtr iph) {
    tcphdrPtr tcph;
    char ipSrcStr [16], ipDestStr [16];

    if (iph->ipProto == IPPROTO_TCP) {
        tcph = (tcphdrPtr) ((u_char *) iph + (iph->iphLen * 4));

        inet_ntop (AF_INET, (void *) &iph->ipSrc, ipSrcStr, sizeof (ipSrcStr));
        inet_ntop (AF_INET, (void *) &iph->ipDest, ipDestStr, sizeof (ipDestStr));

        if (getAppServiceProtoAnalyzer (ipSrcStr, ntohs (tcph->source)) ||
            getAppServiceProtoAnalyzer (ipDestStr, ntohs (tcph->dest)))
            return False;
        else
            return True;
    }

    return False;
}

static ipFragPtr
newIpFrag (iphdrPtr iph) {
    u_short iphLen, ipLen, offset, end;
    u_char *skbuf;
    ipFragPtr ipFragment;

    iphLen = iph->iphLen * 4;
    ipLen = ntohs (iph->ipLen);
    offset = (ntohs (iph->ipOff) & IP_OFFMASK) << 3;
    end = offset + ipLen - iphLen;

    ipFragment = (ipFragPtr) malloc (sizeof (ipFrag));
    if (ipFragment == NULL)
        return NULL;

    ipFragment->offset = offset;
    ipFragment->end = end;
    ipFragment->dataLen = end - offset;
    skbuf = (u_char *) malloc (ipLen);
    if (skbuf == NULL) {
        free (ipFragment);
        return NULL;
    }
    memcpy (skbuf, iph, ipLen);
    ipFragment->dataPtr = skbuf + iphLen;
    ipFragment->skbuf = skbuf;
    initListHead (&ipFragment->node);
    return ipFragment;
}

static void
freeIpFrag (ipFragPtr ipf) {
    free (ipf->skbuf);
    free (ipf);
}

static void
addIpQueueToExpireTimeoutList (ipQueuePtr ipq, timeValPtr tm) {
    ipQueueTimeoutPtr tmp;

    tmp = (ipQueueTimeoutPtr) malloc (sizeof (ipQueueTimeout));
    if (tmp == NULL) {
        LOGE ("Alloc ipQueue expire timeout error: %s.\n", strerror (errno));
        return;
    }

    tmp->queue = ipq;
    tmp->timeout = tm->tvSec + DEFAULT_IPQUEUE_EXPIRE_TIMEOUT;
    listAddTail (&tmp->node, &ipQueueExpireTimeoutList);
}

static void
delIpQueueFromExpireTimeoutList (ipQueuePtr ipq) {
    ipQueueTimeoutPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &ipQueueExpireTimeoutList, node) {
        if (entry->queue == ipq) {
            listDel (&entry->node);
            free (entry);
            return;
        }
    }
}

static void
updateIpQueueExpireTimeout (ipQueuePtr ipq, timeValPtr tm) {
    ipQueueTimeoutPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &ipQueueExpireTimeoutList, node) {
        if (entry->queue == ipq) {
            listDel (&entry->node);
            entry->timeout = tm->tvSec + DEFAULT_IPQUEUE_EXPIRE_TIMEOUT;
            listAddTail (&entry->node, &ipQueueExpireTimeoutList);
            return;
        }
    }
}

static int
addIpQueueToHash (ipQueuePtr ipq, hashItemFreeCB fun) {
    int ret;
    char ipSrcStr [16], ipDestStr [16];
    char key [64];

    inet_ntop (AF_INET, (void *) &ipq->ipSrc, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &ipq->ipDest, ipDestStr, sizeof (ipDestStr));
    snprintf (key, sizeof (key), IPQUEUE_HASH_KEY_FORMAT, ipSrcStr, ipDestStr, ipq->id);
    ret = hashInsert (ipQueueHashTable, key, ipq, fun);
    if (ret < 0)
        return -1;
    else
        return 0;
}

static void
delIpQueueFromHash (ipQueuePtr ipq) {
    int ret;
    char ipSrcStr [16], ipDestStr [16];
    char key [64];

    inet_ntop (AF_INET, (void *) &ipq->ipSrc, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &ipq->ipDest, ipDestStr, sizeof (ipDestStr));
    snprintf (key, sizeof (key), IPQUEUE_HASH_KEY_FORMAT, ipSrcStr, ipDestStr, ipq->id);
    ret = hashRemove (ipQueueHashTable, key);
    if (ret < 0)
        LOGE ("Delete ipQueue from hash table error.\n");
}

static ipQueuePtr
findIpQueue (iphdrPtr iph) {
    char ipSrcStr [16], ipDestStr [16];
    char key [64];

    inet_ntop (AF_INET, (void *) &iph->ipSrc, ipSrcStr, sizeof (ipSrcStr));
    inet_ntop (AF_INET, (void *) &iph->ipDest, ipDestStr, sizeof (ipDestStr));
    snprintf (key, sizeof (key), IPQUEUE_HASH_KEY_FORMAT,
              ipSrcStr, ipDestStr, ntohs (iph->ipId));
    return (ipQueuePtr) hashLookup (ipQueueHashTable, key);
}

static ipQueuePtr
newIpQueue (iphdrPtr iph) {
    ipQueuePtr ipq;

    ipq = (ipQueuePtr) malloc (sizeof (ipQueue));
    if (ipq == NULL)
        return NULL;

    ipq->ipSrc = iph->ipSrc;
    ipq->ipDest = iph->ipDest;
    ipq->id = ntohs (iph->ipId);
    /* Allocate memory for the IP header (plus 8 octets for ICMP). */
    ipq->iph = (iphdrPtr) malloc (64 + 8);
    if (ipq->iph == NULL) {
        free (ipq);
        return NULL;
    }
    ipq->iphLen = 0;
    ipq->dataLen = 0;
    initListHead (&ipq->fragments);
    return ipq;
}

static void
freeIpQueue (void *data) {
    ipFragPtr entry;
    listHeadPtr pos, npos;
    ipQueuePtr ipq = (ipQueuePtr) data;

    delIpQueueFromExpireTimeoutList (ipq);
    listForEachEntrySafe (entry, pos, npos, &ipq->fragments, node) {
        listDel (&entry->node);
        freeIpFrag (entry);
    }
    free (ipq->iph);
    free (ipq);
}

static void
checkIpQueueExpireTimeoutList (timeValPtr tm) {
    ipQueueTimeoutPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &ipQueueExpireTimeoutList, node) {
        if (tm->tvSec < entry->timeout)
            return;
        else
            delIpQueueFromHash (entry->queue);
    }
}

static boolean
ipQueueDone (ipQueuePtr ipq) {
    ipFragPtr entry;
    listHeadPtr pos, npos;
    u_short offset;

    if (!ipq->dataLen)
        return False;

    offset = 0;
    listForEachEntrySafe (entry, pos, npos, &ipq->fragments, node) {
        if (entry->offset != offset)
            return False;
        offset = entry->end;
    }

    return True;
}

/**
 * @brief Glue ip fragments of ipQueue.
 *
 * @param ipq -- ipQueue to glue
 *
 * @return new ip packet if success else NULL
 */
static iphdrPtr
glueIpQueue (ipQueuePtr ipq) {
    u_int ipLen;
    char ipStr [16];
    u_char *buf;
    iphdrPtr iph;
    ipFragPtr entry;
    listHeadPtr pos, npos;

    ipLen = ipq->iphLen + ipq->dataLen;
    if (ipLen > MAX_IP_PACKET_SIZE) {
        inet_ntop (AF_INET, (void *) &ipq->ipSrc, ipStr, sizeof (ipStr));
        LOGE ("Oversized ip packet from %s.\n", ipStr);
        delIpQueueFromHash (ipq);
        return NULL;
    }

    buf = (u_char *) malloc (ipLen);
    if (buf == NULL) {
        LOGE ("Alloc ipQueue buffer error: %s.\n", strerror (errno));
        delIpQueueFromHash (ipq);
        return NULL;
    }

    /* Glue data of all fragments to new ip packet buffer . */
    memcpy (buf, ((u_char *) ipq->iph), ipq->iphLen);
    listForEachEntrySafe (entry, pos, npos, &ipq->fragments, node) {
        memcpy (buf + ipq->iphLen + entry->offset, entry->dataPtr, entry->dataLen);
    }

    iph = (iphdrPtr) buf;
    iph->ipOff = 0;
    iph->ipLen = htons (ipLen);
    delIpQueueFromHash (ipq);

    return iph;
}

static int
checkIpHeader (iphdrPtr iph) {
    u_char ipVer = iph->ipVer;
    u_short iphLen = iph->iphLen * 4;
    u_short ipLen = ntohs (iph->ipLen);

    if (ipVer != 4 || iphLen < sizeof (iphdr) || ipLen < iphLen) {
        LOGE ("IpVer: %d, iphLen: %d, ipLen: %d.\n", ipVer, iphLen, ipLen);
        return -1;
    }

#ifdef DO_STRICT_CHECK
    /* Normally don't do ip checksum, we trust kernel */
    if (ipFastCheckSum ((u_char *) iph, iph->iphl)) {
        LOGE ("ipFastCheckSum error.\n");
        return -1;
    }

    /* Check ip options */
    if (iphLen > sizeof (iphdr) && ipOptionsCompile ((u_char *) iph)) {
        LOGE ("IpOptionsCompile error.\n");
        return -1;
    }
#endif

    return 0;
}

/**
 * @brief Ip packet defragment processor.
 *
 * @param iph -- ip packet header
 * @param tm -- packet capture timestamp
 * @param newIph -- pointer to return ip defragment packet
 *
 * @return 0 if success else -1
 */
int
ipDefragProcess (iphdrPtr iph, timeValPtr tm, iphdrPtr *newIph) {
    int ret;
    timeVal timestamp;
    u_short iphLen, ipLen, offset, end, flags, gap;
    ipFragPtr ipf, prevEntry, entry;
    listHeadPtr pos, npos;
    ipQueuePtr ipq;
    iphdrPtr tmpIph;

    timestamp.tvSec = ntohll (tm->tvSec);
    timestamp.tvUsec = ntohll (tm->tvUsec);

    /* Check ipQueue expire timeout list */
    checkIpQueueExpireTimeoutList (&timestamp);
    ret = checkIpHeader (iph);
    if (ret < 0) {
        *newIph = NULL;
        return -1;
    }

    iphLen = iph->iphLen * 4;
    ipLen = ntohs (iph->ipLen);
    offset = ntohs (iph->ipOff);
    flags = offset & ~IP_OFFMASK;
    offset = (offset & IP_OFFMASK) << 3;
    end = offset + ipLen - iphLen;

    /* Get ipQueue */
    ipq = findIpQueue (iph);

    /* Not a ip fragment */
    if ((flags & IP_MF) == 0 && offset == 0) {
        if (ipq)
            delIpQueueFromHash (ipq);
        if (!doProtoDetect && ipPktShouldDrop (iph))
            *newIph = NULL;
        else
            *newIph = iph;
        return 0;
    }

    displayIphdr (iph);

    if (ipq == NULL) {
        ipq = newIpQueue (iph);
        if (ipq == NULL) {
            LOGE ("Alloc new ipQueue error.\n");
            *newIph = NULL;
            return -1;
        }

        /* Add ipQueue to hash */
        ret = addIpQueueToHash (ipq, freeIpQueue);
        if (ret < 0) {
            LOGE ("Add ipQueue to hash table error.\n");
            *newIph = NULL;
            return -1;
        }

        /* Add ipQueue to expire timeout list */
        addIpQueueToExpireTimeoutList (ipq, &timestamp);
    } else {
        /* Update ipQueue expire timeout */
        updateIpQueueExpireTimeout (ipq, &timestamp);
    }

    /* Alloc new ipFrag */
    ipf = newIpFrag (iph);
    if (ipf == NULL) {
        LOGE ("Create ip fragment error.\n");
        *newIph = NULL;
        return -1;
    }

    /* First packet of fragments */
    if (offset == 0) {
        ipq->iphLen = iphLen;
        memcpy (ipq->iph, iph, iphLen + 8);
    }

    /* Last packet of fragments */
    if ((flags & IP_MF) == 0)
        ipq->dataLen = end;

    /* Find the proper position to insert fragment */
    listForEachEntrySafeKeepPrev (prevEntry, entry, pos, npos, &ipq->fragments, node) {
        if (ipf->offset <= entry->offset)
            break;
    }

    /* Check for overlap with preceding fragment */
    if (prevEntry != NULL && ipf->offset < prevEntry->end) {
        gap = prevEntry->end - ipf->offset;
        /* If previous fragment overlap ipf completely, free ipf and return */
        if (gap >= ipf->dataLen) {
            freeIpFrag (ipf);
            *newIph = NULL;
            return 0;
        }
        ipf->offset += gap;
        ipf->dataLen -= gap;
        ipf->dataPtr += gap;
    }

    /* Check for overlap with succeeding fragments */
    listForEachEntryFromSafe (entry, pos, npos, &ipq->fragments, node) {
        if (ipf->end <= entry->offset)
            break;

        gap = ipf->end - entry->offset;
        /* If ipf overlap succeeding fragment completely, remove it */
        if (gap >= entry->dataLen) {
            listDel (&entry->node);
            freeIpFrag (entry);
        } else {
            entry->offset += gap;
            entry->dataLen -= gap;
            entry->dataPtr += gap;
        }
    }

    /* The proper position to insert ip fragment */
    if (prevEntry == NULL)
        listAdd (&ipf->node, &ipq->fragments);
    else
        listAdd (&ipf->node, &prevEntry->node);

    if (ipQueueDone (ipq)) {
        tmpIph = (iphdrPtr) glueIpQueue (ipq);
        if (tmpIph == NULL) {
            LOGE ("glueIpQueue error.\n");
            *newIph = NULL;
            return -1;
        } else {
            displayIphdr (tmpIph);
            if (!doProtoDetect && ipPktShouldDrop (tmpIph)) {
                free (tmpIph);
                *newIph = NULL;
            } else
                *newIph = tmpIph;
            return 0;
        }
    } else {
        *newIph = NULL;
        return 0;
    }
}

/* Reset ip context */
int
resetIpContext (void) {
    hashClean (ipQueueHashTable);

    return 0;
}

/* Init ip context */
int
initIpContext (boolean protoDetectFlag) {
    doProtoDetect = protoDetectFlag;

    initListHead (&ipQueueExpireTimeoutList);

    ipQueueHashTable = hashNew (DEFAULT_IPQUEUE_HASH_TABLE_SIZE);
    if (ipQueueHashTable == NULL)
        return -1;

    return 0;
}

/* Destroy ip context */
void
destroyIpContext (void) {
    hashDestroy (ipQueueHashTable);
    ipQueueHashTable = NULL;
}
