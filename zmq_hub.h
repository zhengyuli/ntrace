#ifndef __ZMQ_HUB_H__
#define __ZMQ_HUB_H__

#include <stdlib.h>
#include <czmq.h>

#define TASK_STATUS_EXCHANGE_CHANNEL "inproc://taskStatusExchangeChannel"
#define PROTO_DETECTION_STATUS_EXCHANGE_CHANNEL "inproc://protoDetectionStatusExchangeChannel"
#define IP_PACKET_EXCHANGE_CHANNEL "inproc://ipPacketExchangeChannel"
#define ICMP_PACKET_EXCHANGE_CHANNEL "inproc://icmpPacketExchangeChannel"
#define TCP_PACKET_EXCHANGE_CHANNEL "inproc://tcpPacketExchangeChannel"
#define ANALYSIS_RECORD_EXCHANGE_CHANNEL "inproc://analysisRecordExchangeChannel"

#define LOG_RECV_PORT 50001
#define LOG_PUB_PORT 50002
#define TCP_PACKET_DISPATCH_RECV_PORT 51001

typedef struct _zmqHub zmqHub;
typedef zmqHub *zmqHubPtr;

struct _zmqHub {
    zctx_t *zmqCtxt;                    /**< Zmq context */

    void *logRecvSock;                  /**< Log recv sock */
    void *logPubSock;                   /**< Log pub sock */

    void *managementReplySock;          /**< Management reply sock */

    void *taskStatusSendSock;           /**< Task status send sock */
    void *taskStatusRecvSock;           /**< Task status recv sock */

    void *protoDetectionStatusSendSock; /**< Proto detection status send sock */
    void *protoDetectionStatusRecvSock; /**< Proto detection status recv sock */

    void *analysisRecordRecvSock;       /**< Analysis record recv sock */

    void *topologyEntrySendSock;        /**< Topology entry send sock */

    void *appServiceSendSock;           /**< Application service send sock */

    void *ipPktSendSock;                /**< Ip packet send sock */
    void *ipPktRecvSock;                /**< Ip packet recv sock */

    void *icmpPktSendSock;              /**< Icmp packet send sock */
    void *icmpPktRecvSock;              /**< Icmp packet recv sock */
    void *icmpErrorSendSock;            /**< Icmp error send sock */

    void *tcpPktDispatchRecvSock;       /**< Tcp packet dispatch recv sock */

    u_int tcpProcessThreadsNum;         /**< Tcp process threads number */
    u_int *tcpProcessThreadIDsHolder;   /**< Tcp process thread IDs holder */
    void **tcpPktSendSocks;             /**< Tcp packet dispatch send socks */
    void **tcpPktRecvSocks;             /**< Tcp packet dispatch recv socks */
    void **tcpBreakdownSendSocks;       /**< Tcp breakdown send socks */
};

/*========================Interfaces definition============================*/
void *
getLogRecvSock (void);
void *
getLogPubSock (void);
void *
getManagementReplySock (void);
void *
getTaskStatusSendSock (void);
void *
getTaskStatusRecvSock (void);
void *
getProtoDetectionStatusSendSock (void);
void *
getProtoDetectionStatusRecvSock (void);
void *
getAnalysisRecordRecvSock (void);
void *
getTopologyEntrySendSock (void);
void *
getAppServiceSendSock (void);
void *
getIpPktSendSock (void);
void *
getIpPktRecvSock (void);
void *
getIcmpPktSendSock (void);
void *
getIcmpPktRecvSock (void);
void *
getIcmpErrorSendSock (void);
void *
getTcpPktDispatchRecvSock (void);
u_int
getTcpProcessThreadsNum (void);
u_int *
getTcpProcessThreadIDHolder (u_int index);
void *
getTcpPktSendSock (u_int index);
void *
getTcpPktRecvSock (u_int index);
void *
getTcpBreakdownSendSock (u_int index);
int
initZmqHub (void);
void
destroyZmqHub (void);
/*=======================Interfaces definition end=========================*/

#endif /* __ZMQ_HUB_H__ */
