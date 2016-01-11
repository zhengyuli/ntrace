#ifndef __APP_SERVICE_MANAGER_H__
#define __APP_SERVICE_MANAGER_H__

#include <jansson.h>
#include "app_service.h"
#include "proto_analyzer.h"

/*========================Interfaces definition============================*/
protoAnalyzerPtr
getAppServiceProtoAnalyzer (char *ip, u_short port);
appServicePtr
getAppServiceDetected (char *ip, u_short port);
appServicePtr
getAppServiceFromBlacklist (char *ip, u_short port);
char *
getAppServicesPaddingFilter (void);
char *
getAppServicesFilter (void);
json_t *
getJsonFromAppServices (void);
json_t *
getJsonFromAppServicesDetected (void);
json_t *
getJsonFromAppServicesBlacklist (void);
int
updateAppServices (json_t * appServices);
int
updateAppServicesBlacklist (json_t * appServicesBlacklist);
int
addAppServiceDetected (char *ip, u_short port, char *proto);
int
initAppServiceManager (void);
void
destroyAppServiceManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __APP_SERVICE_MANAGER_H__ */
