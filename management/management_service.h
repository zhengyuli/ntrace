#ifndef __MANAGEMENT_SERVICE_H__
#define __MANAGEMENT_SERVICE_H__

#include <czmq.h>

/*=========================================================================*/

/* Management request json key definitions */
#define MANAGEMENT_REQUEST_COMMAND "command"
#define MANAGEMENT_REQUEST_BODY "body"

/* Management request command definitions */
#define MANAGEMENT_REQUEST_COMMAND_RESUME "resume"
#define MANAGEMENT_REQUEST_COMMAND_PAUSE "pause"
#define MANAGEMENT_REQUEST_COMMAND_HEARTBEAT "heartbeat"
#define MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC_INFO "packets_statistic_info"
#define MANAGEMENT_REQUEST_COMMAND_PROTOS_INFO "protos_info"
#define MANAGEMENT_REQUEST_COMMAND_SERVICES_INFO "services_info"
#define MANAGEMENT_REQUEST_COMMAND_SERVICES_BLACKLIST_INFO "services_blacklist_info"
#define MANAGEMENT_REQUEST_COMMAND_DETECTED_SERVICES_INFO "detected_services_info"
#define MANAGEMENT_REQUEST_COMMAND_TOPOLOGY_ENTRIES_INFO "topology_entries_info"
#define MANAGEMENT_REQUEST_COMMAND_UPDATE_SERVICES "update_services"
#define MANAGEMENT_REQUEST_COMMAND_UPDATE_SERVICES_BLACKLIST "update_services_blacklist"

/* Management request body json key definitions */
#define MANAGEMENT_REQUEST_BODY_SERVICES "services"

#define MANAGEMENT_REQUEST_BODY_SERVICES_BLACKLIST "services_blacklist"

/* Management response json key definitions */
#define MANAGEMENT_RESPONSE_CODE "code"
#define MANAGEMENT_RESPONSE_BODY "body"
#define MANAGEMENT_RESPONSE_ERROR_MESSAGE "error_message"

/* Management response body json key definitions */
#define MANAGEMENT_RESPONSE_BODY_PACKETS_RECEIVE "packets_receive"
#define MANAGEMENT_RESPONSE_BODY_PACKETS_DROP "packets_drop"
#define MANAGEMENT_RESPONSE_BODY_PACKETS_DROP_RATE "packets_drop_rate"

#define MANAGEMENT_RESPONSE_BODY_PROTOS "protos"

#define MANAGEMENT_RESPONSE_BODY_SERVICES "services"

#define MANAGEMENT_RESPONSE_BODY_SERVICES_BLACKLIST "services_blacklist"

#define MANAGEMENT_RESPONSE_BODY_DETECTED_SERVICES "detected_services"

#define MANAGEMENT_RESPONSE_BODY_TOPOLOGY_ENTRIES "topology_entries"

/* Default management error response */
#define DEFAULT_MANAGEMENT_ERROR_RESPONSE           \
    "{\"code\":1, \"error_message\":\"internal error\"}"

/*========================Interfaces definition============================*/
void *
managementService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __MANAGEMENT_SERVICE_H__ */
