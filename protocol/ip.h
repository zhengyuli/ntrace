#ifndef __IP_H__
#define __IP_H__

#include <stdint.h>
#include <arpa/inet.h>

typedef struct _iphdr iphdr;
typedef iphdr *iphdrPtr;

struct _iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t iphLen:4;                   /**< Ip header length */
    uint8_t ipVer:4;                    /**< Ip version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ipVer:4;
    uint8_t iphLen:4;
#endif
    uint8_t ipTOS;                      /**< Ip TOS */
    uint16_t ipLen;                     /**< Ip length */
    uint16_t ipId;                      /**< Ip id */
    uint16_t ipOff;                     /**< Ip fragment flag and offset */
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    uint8_t ipTTL;                      /**< Ip TTL */
    uint8_t ipProto;                    /**< Ip proto */
    uint16_t ipChkSum;                  /**< Ip checksum */
    struct in_addr ipSrc;               /**< Ip source */
    struct in_addr ipDest;              /**< Ip dest */
};

#endif /* __IP_H__ */
