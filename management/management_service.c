#include <jansson.h>
#include "config.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "app_service_manager.h"
#include "topology_manager.h"
#include "netdev.h"
#include "proto_analyzer.h"
#include "management_service.h"

/* Packets statistic related variables */
static u_int packetsStatisticPktsReceive = 0;
static u_int packetsStatisticPktsDrop = 0;

/* Proto analyzer information */
static protoAnalyzerInfo protoAnalyzerInformation;

/* Services information */
static json_t *services = NULL;

/* Services blacklist information */
static json_t *servicesBlacklist = NULL;

/* Detected services information */
static json_t *detectedServices = NULL;

/* Topology entries information */
static json_t *topologyEntries = NULL;

/* Error message for response */
static char errMsg [256];

/**
 * @brief Resume request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleResumeRequest (json_t *body) {
    int ret;
    char *filter;

    /* Get Latest application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get application services filter error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Update application services filter */
    ret = updateNetDevFilterForSniff (filter);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Update application services filter error.");
        LOGE ("%s\n", errMsg);
        free (filter);
    }

    LOGI ("\nUpdate application services filter with:\n%s\n", filter);
    free (filter);
    return 0;
}

/**
 * @brief Pause request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handlePauseRequest (json_t *body) {
    int ret;
    char *filter;

    /* Get application services padding filter */
    filter = getAppServicesPaddingFilter ();
    if (filter == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get application services filter error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Update application services filter */
    ret = updateNetDevFilterForSniff (filter);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Update application services filter error.");
        LOGE ("%s\n", errMsg);
        free (filter);
        return -1;
    }

    LOGI ("\nUpdate application services filter with:\n%s\n", filter);
    free (filter);
    return 0;
}

/**
 * @brief Heartbeat request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleHeartbeatRequest (json_t *body) {
    return 0;
}

/**
 * @brief Get packets statistic info request handler.
 *
 * @param  body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleGetPacketsStatisticInfoRequest (json_t *body) {
    int ret;

    ret = getNetDevStatisticInfoForSniff (&packetsStatisticPktsReceive,
                                          &packetsStatisticPktsDrop);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Get packets statistic info error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    return 0;
}

/**
 * @brief Get protos info request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleGetProtosInfoRequest (json_t *body) {
    int ret;

    ret = getProtoAnalyzerInfo (&protoAnalyzerInformation);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Get proto analyzer info error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    return 0;
}

/**
 * @brief Get services info request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleGetServicesInfoRequest (json_t *body) {
    services = getJsonFromAppServices ();
    if (services == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get services info error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    return 0;
}

/**
 * @brief Get services blacklist info request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleGetServicesBlacklistInfoRequest (json_t *body) {
    servicesBlacklist = getJsonFromAppServicesBlacklist ();
    if (servicesBlacklist == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get services blacklist info error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    return 0;
}

/**
 * @brief Get detected services info request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleGetDetectedServicesInfoRequest (json_t *body) {
    detectedServices = getJsonFromAppServicesDetected ();
    if (detectedServices == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get detected services info error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    return 0;
}

/**
 * @brief Get topology entries info request handler.
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleGetTopologyEntriesInfoRequest (json_t *body) {
    topologyEntries = getJsonFromTopologyEntries ();
    if (topologyEntries == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get topology entries info error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    return 0;
}

/**
 * @brief Update services request handler
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleUpdateServicesRequest (json_t *body) {
    int ret;
    json_t *services;
    char *filter;

    /* Check update services permission */
    if (getPropertiesAutoAddService ()) {
        snprintf (errMsg, sizeof (errMsg),
                  "Has no permission to update services for autoAddService=True.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    services = json_object_get (body, MANAGEMENT_REQUEST_BODY_SERVICES);
    if ((services == NULL) || !json_is_array (services)) {
        snprintf (errMsg, sizeof (errMsg), "Invalid format of update services request.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Update application services */
    ret = updateAppServices (services);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Update services error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Get application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get application services filter error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Update application services filter */
    ret = updateNetDevFilterForSniff (filter);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Update application services filter error.");
        LOGE ("%s\n", errMsg);
        free (filter);
        return -1;
    }

    LOGI ("\nUpdate application services filter with:\n%s\n", filter);
    free (filter);
    return 0;
}

/**
 * @brief Update services blacklist request handler
 *
 * @param body -- data to handle
 *
 * @return 0 if success else -1
 */
static int
handleUpdateServicesBlacklistRequest (json_t *body) {
    int ret;
    json_t *servicesBlacklist;
    char *filter;

    /* Check update services blacklist permission */
    if (!getPropertiesAutoAddService ()) {
        snprintf (errMsg, sizeof (errMsg),
                  "Has no permission to update services blacklist for autoAddService=False.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    servicesBlacklist = json_object_get (body, MANAGEMENT_REQUEST_BODY_SERVICES_BLACKLIST);
    if ((servicesBlacklist == NULL) || !json_is_array (servicesBlacklist)) {
        snprintf (errMsg, sizeof (errMsg), "Invalid format of update services blacklist request.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Update application services blacklist */
    ret = updateAppServicesBlacklist (servicesBlacklist);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Update services blacklist error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Get application services filter */
    filter = getAppServicesFilter ();
    if (filter == NULL) {
        snprintf (errMsg, sizeof (errMsg), "Get application services filter error.");
        LOGE ("%s\n", errMsg);
        return -1;
    }

    /* Update application services filter */
    ret = updateNetDevFilterForSniff (filter);
    if (ret < 0) {
        snprintf (errMsg, sizeof (errMsg), "Update application services filter error.");
        LOGE ("%s\n", errMsg);
        free (filter);
        return -1;
    }

    LOGI ("\nUpdate application services filter with:\n%s\n", filter);
    free (filter);
    return 0;
}

/**
 * @brief Build management response based on command.
 *
 * @param cmd -- command for response
 *
 * @return response if success else NULL
 */
static char *
buildManagementResponse (char *cmd, int code) {
    u_int i;
    char *response;
    json_t *root, *body, *protos;
    char buf [128];

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object root error.\n");
        return NULL;
    }

    if (!code) {
        body = json_object ();
        if (body == NULL) {
            LOGE ("Create json object body error.\n");
            json_object_clear (root);
            return NULL;
        }

        if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC_INFO)) {
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PACKETS_RECEIVE,
                                 json_integer (packetsStatisticPktsReceive));
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PACKETS_DROP,
                                 json_integer (packetsStatisticPktsDrop));
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PACKETS_DROP_RATE,
                                 json_real (((double) packetsStatisticPktsDrop /
                                             (double) packetsStatisticPktsReceive) * 100));
        } else if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_PROTOS_INFO)) {
            protos = json_array ();
            if (protos == NULL) {
                LOGE ("Create json array protos error.\n");
                json_object_clear (body);
                json_object_clear (root);
                return NULL;
            }

            for (i = 0; i < protoAnalyzerInformation.protoNum; i++)
                json_array_append_new (protos, json_string (protoAnalyzerInformation.protos [i]));

            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_PROTOS, protos);
        } else if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_SERVICES_INFO)) {
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_SERVICES, services);
            services = NULL;
        } else if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_SERVICES_BLACKLIST_INFO)) {
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_SERVICES_BLACKLIST, servicesBlacklist);
            servicesBlacklist = NULL;
        } else if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_DETECTED_SERVICES_INFO)) {
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_DETECTED_SERVICES, detectedServices);
            detectedServices = NULL;
        } else if (strEqual (cmd, MANAGEMENT_REQUEST_COMMAND_TOPOLOGY_ENTRIES_INFO)) {
            json_object_set_new (body, MANAGEMENT_RESPONSE_BODY_TOPOLOGY_ENTRIES, topologyEntries);
            topologyEntries = NULL;
        }

        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (0));
        json_object_set_new (root, MANAGEMENT_RESPONSE_BODY, body);
    } else if (code == 1) {
        snprintf (buf, sizeof (buf), "Unknown request command: %s", cmd);
        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (1));
        json_object_set_new (root, MANAGEMENT_RESPONSE_ERROR_MESSAGE,
                             json_string (buf));
    } else {
        json_object_set_new (root, MANAGEMENT_RESPONSE_CODE, json_integer (1));
        json_object_set_new (root, MANAGEMENT_RESPONSE_ERROR_MESSAGE,
                             json_string (errMsg));
        errMsg [0] = 0;
    }

    response = json_dumps (root, JSON_INDENT (4) | JSON_PRESERVE_ORDER);

    json_object_clear (root);
    return response;
}

/*
 * Management service.
 */
void *
managementService (void *args) {
    int ret;
    void *managementReplySock;
    char *request, *cmdStr, *response;
    json_t *root, *cmd, *body;
    json_error_t error;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Get management reply sock */
    managementReplySock = getManagementReplySock ();

    while (!taskShouldExit ()) {
        request = zstr_recv (managementReplySock);
        if (request == NULL) {
            if (!taskShouldExit ())
                LOGE ("Receive management request with fatal error.\n");
            break;
        }

        LOGI ("Management request: %s\n", request);

        root = json_loads (request, JSON_DISABLE_EOF_CHECK, &error);
        if (root == NULL) {
            LOGE ("Management request parse error: %s\n", error.text);
            zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
        } else {
            cmd = json_object_get (root, MANAGEMENT_REQUEST_COMMAND);
            body = json_object_get (root, MANAGEMENT_REQUEST_BODY);

            if (cmd == NULL) {
                LOGE ("Invalid format of management request: %s.\n", request);
                zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
            } else {
                cmdStr = (char *) json_string_value (cmd);
                if (strEqual (MANAGEMENT_REQUEST_COMMAND_RESUME, cmdStr))
                    ret = handleResumeRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PAUSE, cmdStr))
                    ret = handlePauseRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_HEARTBEAT, cmdStr))
                    ret = handleHeartbeatRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PACKETS_STATISTIC_INFO, cmdStr))
                    ret = handleGetPacketsStatisticInfoRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_PROTOS_INFO, cmdStr))
                    ret = handleGetProtosInfoRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_SERVICES_INFO, cmdStr))
                    ret = handleGetServicesInfoRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_SERVICES_BLACKLIST_INFO, cmdStr))
                    ret = handleGetServicesBlacklistInfoRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_DETECTED_SERVICES_INFO, cmdStr))
                    ret = handleGetDetectedServicesInfoRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_TOPOLOGY_ENTRIES_INFO, cmdStr))
                    ret = handleGetTopologyEntriesInfoRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_UPDATE_SERVICES, cmdStr))
                    ret = handleUpdateServicesRequest (body);
                else if (strEqual (MANAGEMENT_REQUEST_COMMAND_UPDATE_SERVICES_BLACKLIST, cmdStr))
                    ret = handleUpdateServicesBlacklistRequest (body);
                else {
                    LOGE ("Unknown management request command: %s.\n", cmdStr);
                    ret = 1;
                }

                response = buildManagementResponse (cmdStr, ret);
                if (response == NULL) {
                    LOGE ("Build management response error.\n");
                    zstr_send (managementReplySock, DEFAULT_MANAGEMENT_ERROR_RESPONSE);
                } else {
                    zstr_send (managementReplySock, response);
                    free (response);
                }
            }

            json_object_clear (root);
        }

        free (request);
    }

    LOGI ("ManagementService will exit... .. .\n");
    destroyLogContext ();
exit:
    if (!taskShouldExit ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
