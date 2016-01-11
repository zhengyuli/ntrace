package app_service

import (
	"fmt"
	"encoding/json"
)

const (
	APP_SERVICE_PROTO = "proto"
	APP_SERVICE_IP = "ip"
	APP_SERVICE_PORT = "port"
)

type AppService struct {
	Proto string
	Ip string
	Port uint16
}


/**
 * @brief Convert appService to json.
 *
 * @param svc -- appService to convert
 *
 * @return json object if success, else NULL
 */
json_t *
appService2Json (appServicePtr svc) {
    json_t *root;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* AppService proto */
    json_object_set_new (root, APP_SERVICE_PROTO, json_string (svc->proto));
    /* AppService ip */
    json_object_set_new (root, APP_SERVICE_IP, json_string (svc->ip));
    /* AppService port */
    json_object_set_new (root, APP_SERVICE_PORT, json_integer (svc->port));

    return root;
}

/**
 * @brief Convert json to appService.
 *
 * @param json -- json to convert
 *
 * @return appService if success, else NULL
 */
appServicePtr
json2AppService (json_t *json) {
    json_t *tmp;
    appServicePtr svc;
    protoAnalyzerPtr analyzer;
    struct in_addr sa;

    svc = newAppServiceInternal ();
    if (svc == NULL) {
        LOGE ("Alloc appService error.\n");
        return NULL;
    }

    /* Get appService proto and analyzer */
    tmp = json_object_get (json, APP_SERVICE_PROTO);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_PROTO);
        freeAppService (svc);
        return NULL;
    }
    analyzer = getProtoAnalyzer ((char *) json_string_value (tmp));
    if (analyzer == NULL) {
        LOGE ("Unsupported appService proto type: %s.\n",
              (json_string_value (tmp)));
        freeAppService (svc);
        return NULL;
    }
    svc->proto = analyzer->proto;
    svc->analyzer = analyzer;

    /* Get appService ip */
    tmp = json_object_get (json, APP_SERVICE_IP);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_IP);
        free (svc);
        return NULL;
    }
    if (!inet_aton (json_string_value (tmp), &sa)) {
        LOGE ("Wrong appService ip format: %s.\n",
              (json_string_value (tmp)));
        freeAppService (svc);
        return NULL;
    }
    svc->ip = strdup (json_string_value (tmp));
    if (svc->ip == NULL) {
        LOGE ("Strdup appService ip error: %s.\n",
              strerror (errno));
        freeAppService (svc);
        return NULL;
    }

    /* Get appService port */
    tmp = json_object_get (json, APP_SERVICE_PORT);
    if (tmp == NULL) {
        LOGE ("Has no %s item.\n", APP_SERVICE_PORT);
        freeAppService (svc);
        return NULL;
    }
    svc->port = (u_short) json_integer_value (tmp);

    return svc;
}

/**
 * @brief Get appService analysis record.
 *
 * @param tm -- timestamp
 * @param proto -- appService proto
 * @param ip -- appService ip
 * @param port -- appService port
 *
 * @return analysis record if success, else NULL
 */
char *
appServiceAnalysisRecord (timeValPtr tm, char *proto, char *ip, u_short port) {
    char *out;
    json_t *root;
    char buf [64];

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Analysis record timestamp */
    formatLocalTimeStr (tm, buf, sizeof (buf));
    json_object_set_new (root, ANALYSIS_RECORD_TIMESTAMP,
                         json_string (buf));

    /* Analysis record type */
    json_object_set_new (root, ANALYSIS_RECORD_TYPE,
                         json_string (ANALYSIS_RECORD_TYPE_APP_SERVICE));

    /* AppService proto */
    json_object_set_new (root, APP_SERVICE_PROTO, json_string (proto));

    /* AppService ip */
    json_object_set_new (root, APP_SERVICE_IP, json_string (ip));

    /* AppService port */
    json_object_set_new (root, APP_SERVICE_PORT, json_integer (port));

    out = json_dumps (root, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_object_clear (root);

    return out;
}
