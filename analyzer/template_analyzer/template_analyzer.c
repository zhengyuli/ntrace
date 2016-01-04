#include <stdio.h>
#include <string.h>
#include <jansson.h>
#include <ntrace/util/util.h>
#include <ntrace/log.h>
#include <ntrace/proto_analyzer.h>
#include "template_analyzer.h"

static int
initTemplateAnalyzer (void) {
    LOGI ("Init template analyzer success.\n");
    return 0;
}

static void
destroyTemplateAnalyzer (void) {
    LOGI ("Destroy template analyzer success.\n");
    return;
}

static void *
newTemplateSessionDetail (void) {
    templateSessionDetailPtr dsd;

    dsd = (templateSessionDetailPtr) malloc (sizeof (templateSessionDetail));
    if (dsd == NULL)
        return NULL;

    dsd->exchangeSize = 0;
    dsd->serverTimeBegin = 0;
    dsd->serverTimeEnd = 0;
    return dsd;
}

static void
freeTemplateSessionDetail (void *sd) {
    if (sd == NULL)
        return;

    free (sd);
}

static void *
newTemplateSessionBreakdown (void) {
    templateSessionBreakdownPtr dsbd;

    dsbd = (templateSessionBreakdownPtr) malloc (sizeof (templateSessionBreakdown));
    if (dsbd == NULL) {
        LOGE ("Alloc templateSessionBreakdown error.\n");
        return NULL;
    }

    dsbd->exchangeSize = 0;
    dsbd->serverLatency = 0;
    return dsbd;
}

static void
freeTemplateSessionBreakdown (void *sbd) {
    if (sbd == NULL)
        return;

    free (sbd);
}

static int
generateTemplateSessionBreakdown (void *sd, void *sbd) {
    templateSessionDetailPtr dsd = (templateSessionDetailPtr) sd;
    templateSessionBreakdownPtr dsbd = (templateSessionBreakdownPtr) sbd;

    dsbd->exchangeSize = dsd->exchangeSize;
    dsbd->serverLatency = (u_int) (dsd->serverTimeEnd - dsd->serverTimeBegin);

    return 0;
}

static void
templateSessionBreakdown2Json (json_t *root, void *sd, void *sbd) {
    templateSessionBreakdownPtr dsbd = (templateSessionBreakdownPtr) sbd;

    json_object_set_new (root, TEMPLATE_SBKD_EXCHANGE_SIZE,
                         json_integer (dsbd->exchangeSize));
    json_object_set_new (root, TEMPLATE_SBKD_SERVER_LATENCY,
                         json_integer (dsbd->serverLatency));
}

static void
templateSessionProcessEstb (timeValPtr tm, void *sd) {
    templateSessionDetailPtr dsd = (templateSessionDetailPtr) sd;

    dsd->serverTimeBegin = timeVal2MilliSecond (tm);
}

static void
templateSessionProcessUrgData (streamDirection direction, char urgData,
                               timeValPtr tm, void *sd) {
    return;
}

static u_int
templateSessionProcessData (streamDirection direction, u_char *data, u_int dataLen,
                            timeValPtr tm, void *sd, sessionState *state) {
    templateSessionDetailPtr dsd = (templateSessionDetailPtr) sd;

    dsd->exchangeSize += dataLen;
    return dataLen;
}

static void
templateSessionProcessReset (streamDirection direction, timeValPtr tm, void *sd) {
    templateSessionDetailPtr dsd = (templateSessionDetailPtr) sd;

    dsd->serverTimeEnd = timeVal2MilliSecond (tm);
}

static void
templateSessionProcessFin (streamDirection direction, timeValPtr tm, void *sd,
                           sessionState *state) {
    templateSessionDetailPtr dsd = (templateSessionDetailPtr) sd;

    if (dsd->serverTimeEnd == 0)
        dsd->serverTimeEnd = timeVal2MilliSecond (tm);
    else {
        dsd->serverTimeEnd = timeVal2MilliSecond (tm);
        *state = SESSION_DONE;
    }
}

protoAnalyzer analyzer;

static char *
templateSessionProcessProtoDetect (streamDirection direction, timeValPtr tm,
                                   u_char *data, u_int dataLen) {
    return NULL;
}

protoAnalyzer analyzer = {
    .proto = "TEMPLATE",
    .initProtoAnalyzer = initTemplateAnalyzer,
    .destroyProtoAnalyzer = destroyTemplateAnalyzer,
    .newSessionDetail = newTemplateSessionDetail,
    .freeSessionDetail = freeTemplateSessionDetail,
    .newSessionBreakdown = newTemplateSessionBreakdown,
    .freeSessionBreakdown = freeTemplateSessionBreakdown,
    .generateSessionBreakdown = generateTemplateSessionBreakdown,
    .sessionBreakdown2Json = templateSessionBreakdown2Json,
    .sessionProcessEstb = templateSessionProcessEstb,
    .sessionProcessUrgData = templateSessionProcessUrgData,
    .sessionProcessData = templateSessionProcessData,
    .sessionProcessReset = templateSessionProcessReset,
    .sessionProcessFin = templateSessionProcessFin,
    .sessionProcessProtoDetect = templateSessionProcessProtoDetect
};
