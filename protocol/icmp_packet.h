#ifndef __ICMP_PACKET_H__
#define __ICMP_PACKET_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include "util.h"
#include "ip.h"
#include "icmp.h"

typedef struct _icmpError icmpError;
typedef icmpError *icmpErrorPtr;

struct _icmpError {
    timeVal timestamp;                  /**< Timestamp */
    u_char type;                        /**< Icmp error type */
    u_char code;                        /**< Icmp error code */
    struct in_addr ip;                  /**< Icmp error dest unreachable ip */
    u_short port;                       /**< Icmp error dest unreachable port */
};

/* Icmp error json key definitions */
#define ICMP_ERROR_TYPE "error_type"
#define ICMP_ERROR_CODE "error_code"
#define ICMP_ERROR_DEST_UNREACH_IP "dest_unreach_ip"
#define ICMP_ERROR_DEST_UNREACH_PORT "dest_unreach_port"

typedef enum {
    PUBLISH_ICMP_ERROR
} icmpProcessCallbackArgsType;

typedef struct _icmpProcessCallbackArgs icmpProcessCallbackArgs;
typedef icmpProcessCallbackArgs *icmpProcessCallbackArgsPtr;

struct _icmpProcessCallbackArgs {
    icmpProcessCallbackArgsType type;
    void *args;
};

typedef void (*icmpProcessCB) (icmpProcessCallbackArgsPtr callbackArgs);

/*========================Interfaces definition============================*/
void
icmpProcess (iphdrPtr iph, timeValPtr tm);
int
initIcmpContext (icmpProcessCB fun);
void
destroyIcmpContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __ICMP_PACKET_H__ */
