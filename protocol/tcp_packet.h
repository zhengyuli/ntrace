#ifndef __TCP_PACKET_H__
#define __TCP_PACKET_H__

#include <stdlib.h>
#include <uuid/uuid.h>
#include "util.h"
#include "list.h"
#include "ip.h"
#include "proto_analyzer.h"

typedef enum {
  TCP_SYN_PKT_SENT,
  TCP_SYN_PKT_RECV,
  TCP_CONN_ESTABLISHED,
  TCP_FIN_PKT_SENT,
  TCP_FIN_PKT_CONFIRMED,
  TCP_CONN_CLOSING,
  TCP_CONN_CLOSED
} tcpState;

typedef struct _skbuff skbuff;
typedef skbuff *skbuffPtr;

struct _skbuff {
    u_char *data;                       /**< Skbuff data */
    u_int len;                          /**< Skbuff length */
    u_int seq;                          /**< Skbuff sequence number */
    u_int ack;                          /**< Skbuff ack number */
    u_char urg;                         /**< Skbuff urgency data flag */
    u_short urgPtr;                     /**< Skbuff urgency pointer */
    u_char psh;                         /**< Skbuff push flag */
    u_char fin;                         /**< Skbuff fin flag */
    listHead node;                      /**< Skbuff list node */
};

typedef struct _halfStream halfStream;
typedef halfStream *halfStreamPtr;

struct _halfStream {
    tcpState state;                     /**< Tcp half stream state */
    u_char *rcvBuf;                     /**< Tcp half stream receive buffer */
    u_int bufSize;                      /**< Tcp half stream receive buffer size */
    u_int offset;                       /**< Tcp half stream read offset */
    u_int count;                        /**< Tcp half stream total data received */
    u_int countNew;                     /**< Tcp half stream new data received */
    u_int seq;                          /**< Tcp half stream send sequence number */
    u_int ackSeq;                       /**< Tcp half stream ack sequence number */
    u_int firstDataSeq;                 /**< Tcp half stream first data send sequence number */
    u_int urgCount;                     /**< Tcp half stream urg data received */
    u_int urgCountNew;                  /**< Tcp half stream new urg data count received */
    u_char urgData;                     /**< Tcp half stream new urg data received */
    u_char urgSeen;                     /**< Tcp half stream has new urg data flag */
    u_short urgPtr;                     /**< Tcp half stream urg data pointer */
    u_short window;                     /**< Tcp half stream current window size */
    boolean tsOn;                       /**< Tcp half stream timestamp options on flag */
    boolean wscaleOn;                   /**< Tcp half stream window scale options on flag */
    u_int currTs;                       /**< Tcp half stream current timestamp */
    u_short wscale;                     /**< Tcp half stream window scale size */
    u_short mss;                        /**< Tcp half stream MSS (Maxium Segment Size) */
    listHead head;                      /**< Tcp half stream skbuff list head */
    u_int rmemAlloc;                    /**< Tcp half stream memory allocated for skbuff */
};

typedef struct _tuple4 tuple4;
typedef tuple4 *tuple4Ptr;

struct _tuple4 {
    struct in_addr saddr;               /**< Source ip */
    u_short source;                     /**< Source tcp port */
    struct in_addr daddr;               /**< Dest ip */
    u_short dest;                       /**< Dest tcp port */
};

typedef enum {
    STREAM_INIT,
    STREAM_CONNECTED,
    STREAM_DATA_EXCHANGING,
    STREAM_CLOSING,
    STREAM_TIME_OUT,
    STREAM_CLOSED,
    STREAM_RESET_TYPE1,                 /**< Tcp connection reset type1 (from client and before connected) */
    STREAM_RESET_TYPE2,                 /**< Tcp connection reset type2 (from server and before connected) */
    STREAM_RESET_TYPE3,                 /**< Tcp connection reset type3 (from client and after connected) */
    STREAM_RESET_TYPE4,                 /**< Tcp connection reset type4 (from server and after connected) */
} tcpStreamState;

typedef struct _tcpStream tcpStream;
typedef tcpStream *tcpStreamPtr;

/* Tcp stream */
struct _tcpStream {
    char *proto;                        /**< Tcp application level proto name */
    protoAnalyzerPtr analyzer;          /**< Tcp Appliction level proto analyzer */
    tuple4 addr;                        /**< Tcp stream 4-tuple address */
    uuid_t connId;                      /**< Tcp connection id */
    tcpStreamState state;               /**< Tcp stream state */
    halfStream client;                  /**< Tcp stream client halfStream */
    halfStream server;                  /**< Tcp stream server halfStream */
    u_long_long synTime;                /**< Tcp syn timestamp of three handshake */
    u_int retries;                      /**< Tcp sync retries count */
    u_long_long retriesTime;            /**< Tcp last retry timestamp */
    u_int dupSynAcks;                   /**< Tcp duplicate syn/acks of three handshake */
    u_long_long synAckTime;             /**< Tcp syn/ack timestamp of three handshake */
    u_long_long estbTime;               /**< Tcp establish timestamp */
    u_int mss;                          /**< Tcp MSS */
    u_int c2sBytes;                     /**< Tcp client to server bytes */
    u_int s2cBytes;                     /**< Tcp server to client bytes */
    u_int c2sPkts;                      /**< Tcp client to server packets */
    u_int s2cPkts;                      /**< Tcp server to client packets */
    u_int tinyPkts;                     /**< Tcp tiny packets */
    u_int pawsPkts;                     /**< Tcp PAWS packets */
    u_int retransmittedPkts;            /**< Tcp retransmitted packets */
    u_int outOfOrderPkts;               /**< Tcp out of order packets */
    u_int zeroWindows;                  /**< Tcp zero windows */
    u_int dupAcks;                      /**< Tcp duplicate acks */
    void *sessionDetail;                /**< Tcp appliction session detail */
    boolean inClosingTimeout;           /**< Tcp stream in closing timeout list flag */
    u_long_long closeTime;              /**< Tcp close timestamp */
    listHead node;                      /**< Tcp stream list node */
};

typedef struct _tcpStreamTimeout tcpStreamTimeout;
typedef tcpStreamTimeout *tcpStreamTimeoutPtr;

/* Tcp closing timeout */
struct _tcpStreamTimeout {
    tcpStreamPtr stream;                /**< Tcp stream to close */
    u_long_long timeout;                /**< Tcp stream timeout to close */
    listHead node;                      /**< Tcp stream timeout list node */
};

/* Tcp state for tcp breakdown */
typedef enum {
    TCP_BREAKDOWN_CONNECTED,            /**< Tcp connection connected */
    TCP_BREAKDOWN_DATA_EXCHANGING,      /**< Tcp connection data exchanging */
    TCP_BREAKDOWN_CLOSED,               /**< Tcp connection closed */
    TCP_BREAKDOWN_RESET_TYPE1,          /**< Tcp connection reset type1 (from client and before connected) */
    TCP_BREAKDOWN_RESET_TYPE2,          /**< Tcp connection reset type2 (from server and before connected) */
    TCP_BREAKDOWN_RESET_TYPE3,          /**< Tcp connection reset type3 (from client and after connected) */
    TCP_BREAKDOWN_RESET_TYPE4           /**< Tcp connection reset type4 (from server and after connected) */
} tcpBreakdownState;

typedef struct _tcpBreakdown tcpBreakdown;
typedef tcpBreakdown *tcpBreakdownPtr;

struct _tcpBreakdown {
    timeVal timestamp;                  /**< Timestamp */
    char *proto;                        /**< Tcp application level proto type */
    struct in_addr ipSrc;               /**< Source ip */
    u_short source;                     /**< Source port */
    struct in_addr svcIp;               /**< Service ip */
    u_short svcPort;                    /**< Service port */
    uuid_t connId;                      /**< Tcp connection id */
    tcpBreakdownState state;            /**< Tcp state */
    u_int retries;                      /**< Tcp sync retries */
    u_int retriesLatency;               /**< Tcp sync retries latency in milliseconds */
    u_int dupSynAcks;                   /**< Tcp duplicate syn/ack packages */
    u_int rtt;                          /**< Tcp rtt */
    u_int mss;                          /**< Tcp mss (maxium segment size) */
    u_int connLatency;                  /**< Tcp connection latency in milliseconds */
    u_int c2sBytes;                     /**< Tcp client to server bytes */
    u_int s2cBytes;                     /**< Tcp server to client bytes */
    u_int totalBytes;                   /**< Tcp total bytes */
    u_int c2sPkts;                      /**< Tcp client to server packets */
    u_int s2cPkts;                      /**< Tcp server to client packets */
    u_int totalPkts;                    /**< Tcp total packets */
    u_int tinyPkts;                     /**< Tcp tiny packets */
    u_int pawsPkts;                     /**< Tcp PAWS (Protect Against Wrapped Sequence numbers) packets */
    u_int retransmittedPkts;            /**< Tcp retransmitted packets */
    u_int outOfOrderPkts;               /**< Tcp out of order packets */
    u_int zeroWindows;                  /**< Tcp zero windows */
    u_int dupAcks;                      /**< Tcp duplicate acks */
    void *sessionBreakdown;             /**< Application level session breakdown */
};

/* Tcp breakdown json key definitions */
#define TCP_BKD_PROTO "proto"
#define TCP_BKD_SOURCE_IP "source_ip"
#define TCP_BKD_SOURCE_PORT "source_port"
#define TCP_BKD_SERVICE_IP "service_ip"
#define TCP_BKD_SERVICE_PORT "service_port"
#define TCP_BKD_TCP_CONNECTION_ID "tcp_connection_id"
#define TCP_BKD_TCP_STATE "tcp_state"
#define TCP_BKD_TCP_RETRIES "tcp_retries"
#define TCP_BKD_TCP_RETRIES_LATENCY "tcp_retries_latency"
#define TCP_BKD_TCP_DUPLICATE_SYNACKS "tcp_duplicate_synacks"
#define TCP_BKD_TCP_RTT "tcp_rtt"
#define TCP_BKD_TCP_MSS "tcp_mss"
#define TCP_BKD_TCP_CONNECTION_LATENCY "tcp_connection_latency"
#define TCP_BKD_TCP_C2S_BYTES "tcp_c2s_bytes"
#define TCP_BKD_TCP_S2C_BYTES "tcp_s2c_bytes"
#define TCP_BKD_TCP_TOTAL_BYTES "tcp_total_bytes"
#define TCP_BKD_TCP_C2S_PACKETS "tcp_c2s_packets"
#define TCP_BKD_TCP_S2C_PACKETS "tcp_s2c_packets"
#define TCP_BKD_TCP_TOTAL_PACKETS "tcp_total_packets"
#define TCP_BKD_TCP_TINY_PACKETS "tcp_tiny_packets"
#define TCP_BKD_TCP_PAWS_PACKETS "tcp_paws_packets"
#define TCP_BKD_TCP_RETRANSMITTED_PACKETS "tcp_retransmitted_packets"
#define TCP_BKD_TCP_OUT_OF_ORDER_PACKETS "tcp_out_of_order_packets"
#define TCP_BKD_TCP_ZERO_WINDOWS "tcp_zero_windows"
#define TCP_BKD_TCP_DUPLICATE_ACKS "tcp_duplicate_acks"

typedef enum {
    PUBLISH_TOPOLOGY_ENTRY,
    PUBLISH_APP_SERVICE,
    PUBLISH_TCP_BREAKDOWN
} tcpProcessCallbackArgsType;

typedef struct _tcpProcessCallbackArgs tcpProcessCallbackArgs;
typedef tcpProcessCallbackArgs *tcpProcessCallbackArgsPtr;

struct _tcpProcessCallbackArgs {
    tcpProcessCallbackArgsType type;
    void *args;
};

typedef void (*tcpProcessCB) (tcpProcessCallbackArgsPtr callbackArgs);

/*========================Interfaces definition============================*/
void
tcpProcess (iphdrPtr iph, timeValPtr tm);
int
resetTcpContext (void);
int
initTcpContext (boolean protoDetectFlag, tcpProcessCB fun);
void
destroyTcpContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __TCP_PACKET_H__ */
