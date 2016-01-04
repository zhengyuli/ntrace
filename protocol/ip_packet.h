#ifndef __IP_PACKET_H__
#define __IP_PACKET_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include "util.h"
#include "list.h"
#include "ip.h"

typedef struct _ipFrag ipFrag;
typedef ipFrag *ipFragPtr;

struct _ipFrag {
    u_short offset;                     /**< Ip fragment offset */
    u_short end;                        /**< Ip fragment end */
    u_short dataLen;                    /**< Ip fragment length */
    u_char *dataPtr;                    /**< Ip fragment data */
    u_char *skbuf;                      /**< Ip fragment packet buffer */
    listHead node;                      /**< Ipqueue fragments list node */
};

typedef struct _ipQueue ipQueue;
typedef ipQueue *ipQueuePtr;

struct _ipQueue {
    struct in_addr ipSrc;               /**< Ip source */
    struct in_addr ipDest;              /**< Ip dest */
    u_short id;                         /**< Ip id */
    iphdrPtr iph;                       /**< Ip header */
    u_short iphLen;                     /**< Ip header length */
    u_short dataLen;                    /**< Ip data length */
    listHead fragments;                 /**< Ip fragments list */
};

typedef struct _ipQueueTimeout ipQueueTimeout;
typedef ipQueueTimeout *ipQueueTimeoutPtr;

struct _ipQueueTimeout {
    ipQueuePtr queue;                   /**< Ip fragment queue */
    u_long_long timeout;                /**< Ip fragment queue timeout */
    listHead node;                      /**< Ip fragment queue timout list node */
};

/*========================Interfaces definition============================*/
int
ipDefragProcess (iphdrPtr iph, timeValPtr tm, iphdrPtr *newIph);
int
resetIpContext (void);
int
initIpContext (boolean protoDetectFlag);
void
destroyIpContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __IP_PACKET_H__ */
