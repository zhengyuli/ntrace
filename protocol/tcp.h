#ifndef __TCP_H__
#define __TCP_H__

#include <stdint.h>
#include <arpa/inet.h>

typedef struct _tcphdr tcphdr;
typedef tcphdr *tcphdrPtr;

struct _tcphdr {
    uint16_t source;                    /**< Tcp source port */
    uint16_t dest;                      /**< Tcp dest port */
    uint32_t seq;                       /**< Tcp sequence number */
    uint32_t ackSeq;                    /**< Tcp ack sequence number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;                    /**< Tcp reserved bits */
    uint16_t doff:4;                    /**< Tcp data offset */
    uint16_t fin:1;                     /**< Tcp fin flag */
    uint16_t syn:1;                     /**< Tcp syn flag */
    uint16_t rst:1;                     /**< Tcp reset flag */
    uint16_t psh:1;                     /**< Tcp push flag */
    uint16_t ack:1;                     /**< Tcp ack flag */
    uint16_t urg:1;                     /**< Tcp urgent flag */
    uint16_t res2:2;                    /**< Tcp reserved bits */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#endif
    uint16_t window;                    /**< Tcp window size */
    uint16_t chkSum;                    /**< Tcp checksum */
    uint16_t urgPtr;                    /**< Tcp urgent pointer */
};

#endif /* __TCP_H__ */
