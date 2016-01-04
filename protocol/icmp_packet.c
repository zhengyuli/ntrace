#include <stdlib.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <czmq.h>
#include "util.h"
#include "log.h"
#include "app_service_manager.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"
#include "analysis_record.h"
#include "icmp_packet.h"

/* Icmp process callback function */
static __thread icmpProcessCB icmpProcessCallback;

static char *
getIcmpDestUnreachCodeName (u_char code) {
    switch (code) {
        case ICMP_NET_UNREACH:
            return "ICMP_NET_UNREACH";

        case ICMP_HOST_UNREACH:
            return "ICMP_HOST_UNREACH";

        case ICMP_PROT_UNREACH:
            return "ICMP_PROT_UNREACH";

        case ICMP_PORT_UNREACH:
            return "ICMP_PORT_UNREACH";

        case ICMP_FRAG_NEEDED:
            return "ICMP_FRAG_NEEDED";

        case ICMP_SR_FAILED:
            return "ICMP_SR_FAILED";

        case ICMP_NET_UNKNOWN:
            return "ICMP_NET_UNKNOWN";

        case ICMP_HOST_UNKNOWN:
            return "ICMP_HOST_UNKNOWN";

        case ICMP_HOST_ISOLATED:
            return "ICMP_HOST_ISOLATED";

        case ICMP_NET_ANO:
            return "ICMP_NET_ANO";

        case ICMP_HOST_ANO:
            return "ICMP_HOST_ANO";

        case ICMP_NET_UNR_TOS:
            return "ICMP_NET_UNR_TOS";

        case ICMP_HOST_UNR_TOS:
            return "ICMP_HOST_UNR_TOS";

        case ICMP_PKT_FILTERED:
            return "ICMP_PKT_FILTERED";

        case ICMP_PREC_VIOLATION:
            return "ICMP_PREC_VIOLATION";

        case ICMP_PREC_CUTOFF:
            return "ICMP_PREC_CUTOFF";

        default:
            return "ICMP_CODE_UNKNOWN";
    }
}

static char *
icmpError2AnalysisRecord (icmpErrorPtr error) {
    char *out;
    json_t *root;
    char ipStr [16];
    char buf [64];

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Analysis record timestamp */
    formatLocalTimeStr (&error->timestamp, buf, sizeof (buf));
    json_object_set_new (root, ANALYSIS_RECORD_TIMESTAMP,
                         json_string (buf));

    /* Analysis record type */
    json_object_set_new (root, ANALYSIS_RECORD_TYPE,
                         json_string (ANALYSIS_RECORD_TYPE_ICMP_ERROR));

    /* Icmp error type */
    json_object_set_new (root, ICMP_ERROR_TYPE,
                         json_string ("ICMP_DEST_UNREACH"));

    /* Icmp error code */
    json_object_set_new (root, ICMP_ERROR_CODE,
                         json_string (getIcmpDestUnreachCodeName (error->code)));

    /* Icmp error dest unreach ip */
    inet_ntop (AF_INET, (void *) &error->ip, ipStr, sizeof (ipStr));
    json_object_set_new (root, ICMP_ERROR_DEST_UNREACH_IP,
                         json_string (ipStr));

    /* Icmp error dest unreach port */
    if (error->code == ICMP_PORT_UNREACH)
        json_object_set_new (root, ICMP_ERROR_DEST_UNREACH_PORT,
                             json_integer (error->port));

    out = json_dumps (root, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_object_clear (root);

    return out;
}

static boolean
icmpPktShouldDrop (iphdrPtr iph, tcphdrPtr tcph) {
    char ipStr [16];

    inet_ntop (AF_INET, (void *) &iph->ipDest, ipStr, sizeof (ipStr));

    if (getAppServiceProtoAnalyzer (ipStr, ntohs (tcph->dest)))
        return False;
    else
        return True;
}

/**
 * @brief Icmp pakcet processor.
 *
 * @param iph -- ip packet header
 * @param tm -- packet capture timestamp
 */
void
icmpProcess (iphdrPtr iph, timeValPtr tm) {
    u_int len;
    icmphdrPtr icmph;
    iphdrPtr origIph;
    tcphdrPtr origTcph;
    icmpError error;
    char *record;
    icmpProcessCallbackArgs callbackArgs;

    len = ntohs (iph->ipLen) - iph->iphLen * 4;
    if (len < sizeof (icmphdr)) {
        LOGW ("Incomplete icmp packet.\n");
        return;
    }

    /* Get icmp header */
    icmph = (icmphdrPtr) ((u_char *) iph + iph->iphLen * 4);
    if (icmph->type > NR_ICMP_TYPES ||
        icmph->type != ICMP_DEST_UNREACH ||
        icmph->code > NR_ICMP_UNREACH)
        return;

    len -= sizeof (icmphdr);
    if (len < sizeof (iphdr))
        return;

    /* Get origin ip header */
    origIph = (iphdrPtr) (icmph + 1);
    if (origIph->ipProto != IPPROTO_TCP)
        return;

    error.timestamp.tvSec = ntohll (tm->tvSec);
    error.timestamp.tvUsec = ntohll (tm->tvUsec);
    error.type = icmph->type;
    error.code = icmph->code;
    error.ip = origIph->ipDest;

    if (icmph->code == ICMP_PORT_UNREACH) {
        origTcph = (tcphdrPtr) ((u_char *) origIph + origIph->iphLen * 4);
        if (icmpPktShouldDrop (origIph, origTcph))
            return;
        error.port = ntohs (origTcph->dest);
    }

    record = icmpError2AnalysisRecord (&error);
    if (record) {
        callbackArgs.type = PUBLISH_ICMP_ERROR;
        callbackArgs.args = record;
        (*icmpProcessCallback) (&callbackArgs);
        free (record);
    }
}

int
initIcmpContext (icmpProcessCB fun) {
    icmpProcessCallback = fun;

    return 0;
}

void
destroyIcmpContext (void) {
    return;
}
