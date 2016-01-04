#ifndef __IP_OPTIONS_H__
#define __IP_OPTIONS_H__

#include <stdlib.h>
#include <stdint.h>

#define IPOPT_END       0
#define IPOPT_NOOP      1
#define IPOPT_RR        7
#define IPOPT_TS        68
#define IPOPT_SEC       130
#define IPOPT_LSRR      131
#define IPOPT_SID       136
#define IPOPT_SSRR      137
#define IPOPT_RA        148

#define MAXTTL 255

typedef struct _timestamp timestamp;
typedef timestamp *timestampPtr;

struct _timestamp {
    uint8_t len;
    uint8_t ptr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_t flags:4;
    uint32_t overflow:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint32_t overflow:4;
    uint32_t flags:4;
#endif
    uint32_t data[9];
};

#define MAX_ROUTE	16

typedef struct _route route;
typedef route *routePtr;

struct _route {
    uint8_t routeSize;
    uint8_t pointer;
    uint32_t route [MAX_ROUTE];
};

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4

#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TIMESTAMP IPOPT_TS

#define IPOPT_TS_TSONLY    0    /* timestamps only */
#define IPOPT_TS_TSANDADDR 1    /* timestamps and addresses */
#define IPOPT_TS_PRESPEC   3    /* specified modules only */

#define MAX_IPOPTLEN 40

typedef struct _ipOptions ipOptions;
typedef ipOptions *ipOptionsPtr;

struct _ipOptions {
    uint32_t faddr;                     /**< Saved first hop address */
    uint8_t optLen;
    uint8_t srr;
    uint8_t rr;
    uint8_t ts;
    uint8_t isSetbyuser:1;              /**< Set by setsockopt */
    uint8_t isData:1;                   /**< Options in data, rather than skb */
    uint8_t isStrictRoute:1;            /**< Strict source route */
    uint8_t srrIsHit:1;                 /**< Packet destination addr was our one */
    uint8_t isChanged:1;                /**< IP checksum more not valid */
    uint8_t rrNeedAddr:1;               /**< Need to record addr of outgoing dev */
    uint8_t tsNeedTime:1;               /**< Need to record timestamp */
    uint8_t tsNeedAddr:1;               /**< Need to record addr of outgoing dev */
    uint8_t pad1;
    uint8_t pad2;
    uint8_t pad3;
    uint8_t data [0];
};

/*========================Interfaces definition============================*/
int
ipOptionsCompile (u_char *iph);
/*=======================Interfaces definition end=========================*/

#endif /* __IP_OPTIONS_H__ */
