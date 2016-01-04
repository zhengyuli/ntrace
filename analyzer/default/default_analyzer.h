#ifndef __DEFAULT_ANALYZER_H__
#define __DEFAULT_ANALYZER_H__

#include "proto_analyzer.h"

typedef struct _defaultSessionDetail defaultSessionDetail;
typedef defaultSessionDetail *defaultSessionDetailPtr;

struct _defaultSessionDetail {
    u_int exchangeSize;                 /**< Default data size exchanged between client and server */
    u_long_long serverTimeBegin;        /**< Default server time begin */
    u_long_long serverTimeEnd;          /**< Default server time end */
};

typedef struct _defaultSessionBreakdown defaultSessionBreakdown;
typedef defaultSessionBreakdown *defaultSessionBreakdownPtr;

struct _defaultSessionBreakdown {
    u_int exchangeSize;                 /**< Default data size exchanged */
    u_int serverLatency;                /**< Default server latency */
};

/* Default session breakdown json key definitions */
#define DEFAULT_SBKD_EXCHANGE_SIZE "default_exchange_size"
#define DEFAULT_SBKD_SERVER_LATENCY "default_server_latency"

#endif /* __DEFAULT_ANALYZER_H__ */
