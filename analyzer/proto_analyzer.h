#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <stdlib.h>
#include <jansson.h>
#include "util/util.h"

#define MAX_PROTO_ANALYZER_NUM 512

typedef enum {
    STREAM_FROM_CLIENT = 0,
    STREAM_FROM_SERVER = 1
} streamDirection;

typedef enum {
    SESSION_ACTIVE = 0,
    SESSION_DONE = 1
} sessionState;

typedef struct _protoAnalyzerInfo protoAnalyzerInfo;
typedef protoAnalyzerInfo *protoAnalyzerInfoPtr;

struct _protoAnalyzerInfo {
    char protos [MAX_PROTO_ANALYZER_NUM][32];
    u_int protoNum;
};

/*=================Proto analyzer callbacks definition=====================*/
/**
 * @brief Proto analyzer init function.
 *        This callback will be called when proto analyzer module
 *        load this proto analyzer and do proto analyzer initialization.
 *
 * @return 0 if success else -1
 */
typedef int (*initProtoAnalyzerCB) (void);

/**
 * @brief Proto analyzer destroy function.
 *        This callback will be called when proto analyzer module exit,
 *        it will destroy proto analyzer context.
 */
typedef void (*destroyProtoAnalyzerCB) (void);

/**
 * @brief Create new session detail.
 *        This callback will be called when tcp session is created, it
 *        will create a new session detail to track the session process.
 */
typedef void * (*newSessionDetailCB) (void);

/**
 * @brief Destroy session detail.
 *        This callback will be called when tcp session is closed, it
 *        will destroy the session detail allocated before.
 */
typedef void (*freeSessionDetailCB) (void *sd);

/**
 * @brief Create new session breakdown.
 *        This callback will be called when tcp session breakdown is created,
 *        it will create a new session breakdown to hold breakdown information
 *        of current proto.
 */
typedef void * (*newSessionBreakdownCB) (void);

/**
 * @brief Destroy session breakdown.
 *        This callback will be called when tcp session breakdown is destroyed,
 *        it will destroy the session breakdown allocated before.
 */
typedef void (*freeSessionBreakdownCB) (void *sbd);

/**
 * @brief Generate session breakdown.
 *        This callback will be called when tcp session breakdown is generated,
 *        it will generate session breakdown by session detail.
 *
 * @return 0 if success else -1
 */
typedef int (*generateSessionBreakdownCB) (void *sd, void *sbd);

/**
 * @brief Convert session breakdown to json.
 *        This callback will be called when tcp session breakdown is generated,
 *        it will convert session breakdown to json format.
 *
 * @param root -- json root
 * @param sd -- session detail
 * @param sbd -- session breakdown
 */
typedef void (*sessionBreakdown2JsonCB) (json_t *root, void *sd, void *sbd);

/**
 * @brief Tcp connection establish callback.
 *        This callback will be called when tcp connection is established.
 *
 * @param tm -- timestamp
 * @param sd -- session detail
 */
typedef void (*sessionProcessEstbCB) (timeValPtr tm, void *sd);

/**
 * @brief Tcp urgency data process callback.
 *        This callback will be called when receive tcp urgency data.
 *
 * @param direction --data flow direction
 * @param urgData --urgency data
 * @param tm -- timestamp
 * @param sd -- session detail
 */
typedef void (*sessionProcessUrgeDataCB) (streamDirection direction, char urgData,
                                          timeValPtr tm, void *sd);

/**
 * @brief Tcp data process callback.
 *        This callback will be called when receive application proto data, this callback
 *        will process data and return data length has been processed. if data process is
 *        done, set state to SESSION_DONE to generate session breakdown, else  set to
 *        SESSION_ACTIVE.
 *
 * @param direction -- data flow direction
 * @param data -- application proto data
 * @param dataLen -- application proto data length
 * @param tm -- timestamp
 * @param sd -- session detail
 * @param state -- pointer to get session state
 *
 * @return data length has been processed
 */
typedef u_int (*sessionProcessDataCB) (streamDirection direction, u_char *data, u_int dataLen,
                                       timeValPtr tm, void *sd, sessionState *state);

/**
 * @brief Tcp reset process callback.
 *        This callback will be called when tcp connection is reset.
 *
 * @param direction -- data flow direction
 * @param tm -- timestamp
 * @param sd -- session detail
 */
typedef void (*sessionProcessResetCB) (streamDirection direction, timeValPtr tm, void *sd);

/**
 * @brief Tcp finish process callback.
 *        This callback will be called when tcp fin packet is received.
 *        If session is complete, set state to SESSION_DONE, else set to
 *        SESSION_ACTIVE.
 *
 * @param direction -- data flow direction
 * @param tm -- timestamp
 * @param sd -- session detail
 * @param state -- pointer to set session state
 */
typedef void (*sessionProcessFinCB) (streamDirection direction, timeValPtr tm, void *sd,
                                     sessionState *state);

/**
 * @brief Tcp proto detect process callback.
 *        This callback will be called when receive application proto data,
 *        it will check proto data and return proto name if proto detected.
 *
 * @param direction -- data flow direction
 * @param data -- application proto data
 * @param dataLen -- application proto data length
 *
 * @return proto name if detected, else NULL
 */
typedef char * (*sessionProcessProtoDetectCB) (streamDirection direction, timeValPtr tm,
                                               u_char *data, u_int dataLen);

/*===============Proto analyzer callbacks definition end===================*/

typedef struct _protoAnalyzer protoAnalyzer;
typedef protoAnalyzer *protoAnalyzerPtr;

/* Proto analyzer callback */
struct _protoAnalyzer {
    char proto [32];                                       /**< Protocol name */
    initProtoAnalyzerCB initProtoAnalyzer;                 /**< Protocol init callback */
    destroyProtoAnalyzerCB destroyProtoAnalyzer;           /**< Protocol destroy callback */
    newSessionDetailCB newSessionDetail;                   /**< Create new session detail callback */
    freeSessionDetailCB freeSessionDetail;                 /**< Free session detail callback */
    newSessionBreakdownCB newSessionBreakdown;             /**< Create new session breakdown callback */
    freeSessionBreakdownCB freeSessionBreakdown;           /**< Free session breakdown callback */
    generateSessionBreakdownCB generateSessionBreakdown;   /**< Generate session breakdown callback */
    sessionBreakdown2JsonCB sessionBreakdown2Json;         /**< Translate session breakdown to json callback */
    sessionProcessEstbCB sessionProcessEstb;               /**< Tcp establishment callback */
    sessionProcessUrgeDataCB sessionProcessUrgData;        /**< Urgency data processing callback */
    sessionProcessDataCB sessionProcessData;               /**< Data processing callback */
    sessionProcessResetCB sessionProcessReset;             /**< Tcp reset processing callback */
    sessionProcessFinCB sessionProcessFin;                 /**< Tcp fin processing callback */
    sessionProcessProtoDetectCB sessionProcessProtoDetect; /**< Tcp proto detect processing callback */
};

/*========================Interfaces definition============================*/
int
getProtoAnalyzerInfo (protoAnalyzerInfoPtr info);
protoAnalyzerPtr
getProtoAnalyzer (char *proto);
char *
protoDetect (streamDirection direction, timeValPtr tm,
             u_char *data, u_int dataLen);
int
initProtoAnalyzer (void);
void
destroyProtoAnalyzer (void);
/*=======================Interfaces definition end=========================*/

#endif /* __PROTOCOL_H__ */
