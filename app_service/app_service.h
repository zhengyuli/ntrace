#ifndef __APP_SERVICE_H__
#define __APP_SERVICE_H__

#include <stdlib.h>
#include <jansson.h>
#include "proto_analyzer.h"

typedef struct _appService appService;
typedef appService *appServicePtr;

/* AppService definition */
struct _appService {
    char *proto;                        /**< AppService proto name */
    protoAnalyzerPtr analyzer;          /**< AppService proto analyzer */
    char *ip;                           /**< AppService ip */
    u_short port;                       /**< AppService port */
};

/* AppService json key definitions */
#define APP_SERVICE_PROTO "proto"
#define APP_SERVICE_IP "ip"
#define APP_SERVICE_PORT "port"

/*========================Interfaces definition============================*/
appServicePtr
newAppService (char *ip, u_short port, char *proto);
void
freeAppService (appServicePtr svc);
appServicePtr
copyAppService (appServicePtr appService);
void
freeAppServiceForHash (void *data);
json_t *
appService2Json (appServicePtr svc);
appServicePtr
json2AppService (json_t *json);
char *
appServiceAnalysisRecord (timeValPtr tm, char *proto, char *ip, u_short port);
/*=======================Interfaces definition end=========================*/

#endif /* __APP_SERVICE_H__ */
