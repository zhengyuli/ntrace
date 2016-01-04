#include <net/if.h>
#include <pcap.h>
#include "log.h"
#include "properties.h"
#include "netdev.h"

/* Pcap configs */
#define PCAP_MAX_CAPTURE_LENGTH 65535
#define PCAP_CAPTURE_TIMEOUT 500
#define PCAP_CAPTURE_IN_PROMISC 1
#define PCAP_CAPTURE_BUFFER_SIZE (32 << 20)

/* Pcap descriptor for sniff */
static pcap_t *pcapDescForSniff = NULL;
/* Datalink type for sniff */
static int datalinkTypeForSniff = -1;

/* Pcap descriptor for proto detection */
static pcap_t *pcapDescForProtoDection = NULL;
/* Datalink type for proto detection */
static int datalinkTypeForProtoDetection = -1;

/**
 * @brief Create a pcap descriptor from pcap file.
 *
 * @param pcapFile -- pcap file
 *
 * @return pcap descriptor
 */
static pcap_t *
newPcapFileDesc (char *pcapFile) {
    pcap_t *pcapDesc;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    pcapDesc = pcap_open_offline (pcapFile, errBuf);
    if (pcapDesc == NULL)
        LOGE ("%s\n", errBuf);

    return pcapDesc;
}

/**
 * @brief Create a pcap descriptor from network Interface.
 *
 * @param interface -- network Interface
 *
 * @return pcap descriptor
 */
static pcap_t *
newPcapInterfaceDesc (char *interface) {
    int ret;
    pcap_t *pcapDesc;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    /* Check interface exists */
    ret = pcap_findalldevs (&alldevs, errBuf);
    if (ret < 0) {
        LOGE ("No network devices found: %s.\n", errBuf);
        return NULL;
    }

    for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
        if (strEqual (devptr->name, interface))
            break;
    }
    if (devptr == NULL) {
        LOGE ("Interface \"%s\" not found.\nInterfaces possible: ", interface);
        for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
            if (devptr->next)
                LOGE ("\"%s\", ", devptr->name);
            else
                LOGE ("\"%s\"\n", devptr->name);
        }
        return NULL;
    }

    /* Create pcap descriptor */
    pcapDesc = pcap_create (interface, errBuf);
    if (pcapDesc == NULL) {
        LOGE ("Create pcap descriptor error: %s.\n", errBuf);
        return NULL;
    }

    /* Set pcap max capture length */
    ret = pcap_set_snaplen (pcapDesc, PCAP_MAX_CAPTURE_LENGTH);
    if (ret < 0) {
        LOGE ("Set pcap snaplen error\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Set pcap promisc mode */
    ret = pcap_set_promisc (pcapDesc, PCAP_CAPTURE_IN_PROMISC);
    if (ret < 0) {
        LOGE ("Set pcap promisc mode error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Set pcap timeout */
    ret = pcap_set_timeout (pcapDesc, PCAP_CAPTURE_TIMEOUT);
    if (ret < 0) {
        LOGE ("Set capture timeout error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Set pcap buffer size */
    ret = pcap_set_buffer_size (pcapDesc, PCAP_CAPTURE_BUFFER_SIZE);
    if (ret < 0) {
        LOGE ("Set pcap capture buffer size error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Activate pcap descriptor */
    ret = pcap_activate (pcapDesc);
    if (ret < 0) {
        LOGE ("Activate pcap descriptor error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    return pcapDesc;
}

/* Get netDev descriptor for sniff */
pcap_t *
getNetDevPcapDescForSniff (void) {
    return pcapDescForSniff;
}

/* Get netDev descriptor for proto detection */
pcap_t *
getNetDevPcapDescForProtoDetection (void) {
    return pcapDescForProtoDection;
}

/* Get netDev data link type for sniff */
int
getNetDevDatalinkTypeForSniff (void) {
    return datalinkTypeForSniff;
}

/* Get netDev data link type for proto detection */
int
getNetDevDatalinkTypeForProtoDetection (void) {
    return datalinkTypeForProtoDetection;
}

/**
 * @brief Get pcapDev statistic info for sniff.
 *
 * @param pcapDev -- pcap descriptor
 * @param pktsRecv -- pointer to return packets received
 * @param pktsDrop -- pointer to return packets dropped
 *
 * @return 0 if success else -1
 */
static int
getPcapStatisticInfo (pcap_t *pcapDev, u_int *pktsRecv, u_int *pktsDrop) {
    int ret;
    struct pcap_stat ps;

    ret = pcap_stats (pcapDev, &ps);
    if (ret < 0)
        return -1;

    *pktsRecv = ps.ps_recv;
    *pktsDrop = ps.ps_drop;
    return 0;
}

/* Get netDev statistic info for sniff */
int
getNetDevStatisticInfoForSniff (u_int *pktsRecv, u_int *pktsDrop) {
    return getPcapStatisticInfo (pcapDescForSniff, pktsRecv, pktsDrop);
}

/* Get netDev statistic info for proto detection */
int
getNetDevStatisticInfoForProtoDetection (u_int *pktsRecv, u_int *pktsDrop) {
    return getPcapStatisticInfo (pcapDescForProtoDection, pktsRecv, pktsDrop);
}

/**
 * @brief Update pcapDev BPF filter.
 *
 * @param pcapDev -- pcap descriptor
 * @param filter -- BPF filter to update
 *
 * @return 0 if success else -1
 */
static int
updatePcapFilter (pcap_t *pcapDev, char *filter) {
    int ret;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct bpf_program pcapFilter;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    if (getPropertiesSniffLive ()) {
        ret = pcap_lookupnet (getPropertiesInterface (), &net, &mask, errBuf);
        if (ret < 0) {
            LOGE ("Pcap lookup net error.\n");
            return -1;
        }
    } else
        mask = PCAP_NETMASK_UNKNOWN;

    ret = pcap_compile (pcapDev, &pcapFilter, filter, 1, mask);
    if (ret < 0) {
        LOGE ("Pcap compile error.\n");
        return -1;
    }

    ret = pcap_setfilter (pcapDev, &pcapFilter);
    pcap_freecode (&pcapFilter);
    return ret;
}

/* Update netDev BPF filter for sniff */
int
updateNetDevFilterForSniff (char *filter) {
    return updatePcapFilter (pcapDescForSniff, filter);
}

/* Update netDev BPF filter for proto detection */
int
updateNetDevFilterForProtoDetection (char *filter) {
    return updatePcapFilter (pcapDescForProtoDection, filter);
}

/**
 * @brief Reset netDev for sniff, only for pcap file.
 *
 * @return 0 for success, -1 for error, 1 for complete
 */
int
resetNetDevForSniff (void) {
    pcap_t * tmp;

    if (getPropertiesSniffLive ())
        tmp = newPcapInterfaceDesc (getPropertiesInterface ());
    else
        tmp = newPcapFileDesc (getPropertiesPcapFile ());
    if (tmp == NULL) {
        LOGE ("Create pcap descriptor for %s error.\n",
              getPropertiesSniffLive () ? getPropertiesInterface () : getPropertiesPcapFile ());
        return -1;
    }

    if (pcapDescForSniff)
        pcap_close (pcapDescForSniff);

    pcapDescForSniff = tmp;
    return 0;
}

/**
 * @brief Init netDev.
 *        Init netDev for sniff and proto detection from pcap file
 *        or network interface, if pcap file is configured, it will
 *        create a pcap file descriptor, else if will create a network
 *        Interface descriptor.
 *
 * @return 0 if success else -1
 */
int
initNetDev (void) {
    if (getPropertiesSniffLive ()) {
        pcapDescForSniff = newPcapInterfaceDesc (getPropertiesInterface ());
        if (pcapDescForSniff == NULL) {
            LOGE ("Open interface: %s for sniff error.\n",
                  getPropertiesInterface ());
            return -1;
        } else
            LOGI ("Use interface: %s as input for sniff.\n",
                  getPropertiesInterface ());

        pcapDescForProtoDection = newPcapInterfaceDesc (getPropertiesInterface ());
        if (pcapDescForProtoDection == NULL) {
            pcap_close (pcapDescForSniff);
            pcapDescForSniff = NULL;
            LOGE ("Open interface: %s for proto detection error.\n",
                  getPropertiesInterface ());
            return -1;
        } else
            LOGI ("Use interface: %s as input for proto detection.\n",
                  getPropertiesInterface ());
    } else {
        pcapDescForSniff = newPcapFileDesc (getPropertiesPcapFile ());
        if (pcapDescForSniff == NULL) {
            LOGE ("Open pcap file for sniff error.\n");
            return -1;
        } else
            LOGI ("Use pcap file: %s as input for sniff.\n",
                  getPropertiesPcapFile ());

        pcapDescForProtoDection = newPcapFileDesc (getPropertiesPcapFile ());
        if (pcapDescForProtoDection == NULL) {
            pcap_close (pcapDescForSniff);
            pcapDescForSniff = NULL;
            LOGE ("Open pcap file for proto detection error.\n");
            return -1;
        } else {
            LOGI ("Use pcap file: %s as input for proto detection.\n",
                  getPropertiesPcapFile ());
        }
    }

    /* Get datalink type for sniff and proto detection */
    datalinkTypeForSniff = pcap_datalink (pcapDescForSniff);
    datalinkTypeForProtoDetection = pcap_datalink (pcapDescForProtoDection);

    if (datalinkTypeForSniff < 0 ||
        datalinkTypeForProtoDetection < 0) {
        LOGE ("Get datalink type error.\n");

        pcap_close (pcapDescForSniff);
        pcapDescForSniff = NULL;
        pcap_close (pcapDescForProtoDection);
        pcapDescForProtoDection = NULL;
        return -1;
    }

    return 0;
}

/* Destroy netDev for sniff and proto detection */
void
destroyNetDev (void) {
    if (pcapDescForSniff) {
        pcap_close (pcapDescForSniff);
        pcapDescForSniff = NULL;
    }

    if (pcapDescForProtoDection) {
        pcap_close (pcapDescForProtoDection);
        pcapDescForProtoDection = NULL;
    }
}
