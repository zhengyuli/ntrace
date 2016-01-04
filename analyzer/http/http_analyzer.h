#ifndef __HTTP_ANALYZER_H__
#define __HTTP_ANALYZER_H__

#include "util.h"
#include "list.h"
#include "http_parser.h"
#include "proto_analyzer.h"

#define HTTP_VERSION_LENGTH 16

typedef enum {
    HTTP_HEADER_HOST = 1,
    HTTP_HEADER_USER_AGENT,
    HTTP_HEADER_REFERER,
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_ACCEPT_LANGUAGE,
    HTTP_HEADER_ACCEPT_ENCODING,
    HTTP_HEADER_X_FORWARDED_FOR,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_CONTENT_DISPOSITION,
    HTTP_HEADER_TRANSFER_ENCODING,
    HTTP_HEADER_CONNECTION,
    HTTP_HEADER_IGNORE
} httpHeaderType;

#define HTTP_HEADER_HOST_STRING "Host"
#define HTTP_HEADER_USER_AGENT_STRING "User-Agent"
#define HTTP_HEADER_REFERER_STRING "Referer"
#define HTTP_HEADER_ACCEPT_STRING "Accept"
#define HTTP_HEADER_ACCEPT_LANGUAGE_STRING "Accept-Language"
#define HTTP_HEADER_ACCEPT_ENCODING_STRING "Accept-Encoding"
#define HTTP_HEADER_X_FORWARDED_FOR_STRING "X-Forwarded-For"
#define HTTP_HEADER_CONTENT_TYPE_STRING "Content-Type"
#define HTTP_HEADER_CONTENT_DISPOSITION_STRING "Content-Disposition"
#define HTTP_HEADER_TRANSFER_ENCODING_STRING "Transfer-Encoding"
#define HTTP_HEADER_CONNECTION_STRING "Connection"

typedef enum {
    HTTP_INIT = 0,                      /**< Http init state */
    HTTP_REQUEST_HEADER_BEGIN,          /**< Http request header begin*/
    HTTP_REQUEST_HEADER_COMPLETE,       /**< Http request header complete */
    HTTP_REQUEST_BODY_BEGIN,            /**< Http request body begin */
    HTTP_REQUEST_BODY_COMPLETE,         /**< Http request complete */
    HTTP_RESPONSE_HEADER_BEGIN,         /**< Http response header begin */
    HTTP_RESPONSE_HEADER_COMPLETE,      /**< Http response header complete */
    HTTP_RESPONSE_BODY_BEGIN,           /**< Http response body beigin */
    HTTP_RESPONSE_BODY_COMPLETE,        /**< Http response complete */
    HTTP_RESET_TYPE1,                   /**< Http reset during request */
    HTTP_RESET_TYPE2,                   /**< Http reset after request and before response */
    HTTP_RESET_TYPE3,                   /**< Http reset during response */
    HTTP_RESET_TYPE4                    /**< Http reset without request */
} httpSessionState;

typedef struct _httpSessionDetailNode httpSessionDetailNode;
typedef httpSessionDetailNode *httpSessionDetailNodePtr;

struct _httpSessionDetailNode {
    char *reqVer;                       /**< Http protocol request version */
    char *method;                       /**< Http request method */
    char *uri;                          /**< Http request uri */
    char *host;                         /**< Http server host */
    char *userAgent;                    /**< Http request user agent */
    char *referer;                      /**< Http request referer url */
    char *accept;                       /**< Http request accept sources */
    char *acceptLanguage;               /**< Http request accept language */
    char *acceptEncoding;               /**< Http request accept encoding */
    char *xForwardedFor;                /**< Http request x forwarded for */
    char *reqConnection;                /**< Http request connection */
    char *respVer;                      /**< Http protocol response version */
    char *contentType;                  /**< Http response content type */
    char *contentDisposition;           /**< Http response content disposition */
    char *transferEncoding;             /**< Http response transfer encoding */
    char *respConnection;               /**< Http response connection */
    httpSessionState state;             /**< Http state */
    u_short statusCode;                 /**< Http status code */
    u_long_long reqTime;                /**< Http request time */
    u_int reqHeaderSize;                /**< Http request header size */
    u_int reqBodySize;                  /**< Http request body size */
    u_long_long respTimeBegin;          /**< Http response time begin */
    u_int respHeaderSize;               /**< Http response header size */
    u_int respBodySize;                 /**< Http response body size */
    u_long_long respTimeEnd;            /**< Http response time end */
    listHead node;                      /**< Http session detail node */
};

typedef struct _httpSessionDetail httpSessionDetail;
typedef httpSessionDetail *httpSessionDetailPtr;

/* Http session detail */
struct _httpSessionDetail {
    http_parser reqParser;                   /**< Http request parser */
    http_parser_settings reqParserSettings;  /**< Http request parser settings */
    http_parser resParser;                   /**< Http response parser */
    http_parser_settings resParserSettings;  /**< Http response parser settings */
    listHead head;                           /**< HttpSessionDetailNode list */
};

typedef enum {
    HTTP_BREAKDOWN_OK = 0,              /**< Http request ok */
    HTTP_BREAKDOWN_ERROR,               /**< Http request error */
    HTTP_BREAKDOWN_RESET_TYPE1,         /**< Http reset during request */
    HTTP_BREAKDOWN_RESET_TYPE2,         /**< Http reset after request and before response */
    HTTP_BREAKDOWN_RESET_TYPE3,         /**< Http reset during response */
    HTTP_BREAKDOWN_RESET_TYPE4          /**< Http reset without request */
} httpBreakdownState;

typedef struct _httpSessionBreakdown httpSessionBreakdown;
typedef httpSessionBreakdown *httpSessionBreakdownPtr;

/* Http session time breakdown */
struct _httpSessionBreakdown {
    char *reqVer;                       /**< Http protocol request version */
    char *method;                       /**< Http request method */
    char *uri;                          /**< Http request uri */
    char *host;                         /**< Http server host */
    char *userAgent;                    /**< Http request user agent */
    char *referer;                      /**< Http request referer url */
    char *accept;                       /**< Http request accept sources */
    char *acceptLanguage;               /**< Http request accept language */
    char *acceptEncoding;               /**< Http request accept encoding */
    char *xForwardedFor;                /**< Http request x forwarded for */
    char *reqConnection;                /**< Http request connection */
    char *respVer;                      /**< Http protocol response version */
    char *contentType;                  /**< Http response content type */
    char *contentDisposition;           /**< Http response content disposition */
    char *transferEncoding;             /**< Http response transfer encoding */
    char *respConnection;               /**< Http response connection */
    httpBreakdownState state;           /**< Http state */
    u_short statusCode;                 /**< Http status code */
    u_int reqHeaderSize;                /**< Http request heaer size */
    u_int reqBodySize;                  /**< Http request body size */
    u_int respHeaderSize;               /**< Http response header size */
    u_int respBodySize;                 /**< Http response body size */
    u_int serverLatency;                /**< Http server latency */
    u_int downloadLatency;              /**< Http response download latency */
    u_int respLatency;                  /**< Http response latency */
};

/* Http session breakdown json key definitions */
#define HTTP_SBKD_REQUEST_VERSION "http_request_version"
#define HTTP_SBKD_METHOD "http_method"
#define HTTP_SBKD_URI "http_uri"
#define HTTP_SBKD_HOST "http_host"
#define HTTP_SBKD_REQUEST_LINE "http_request_line"
#define HTTP_SBKD_USER_AGENT "http_user_agent"
#define HTTP_SBKD_REFERER "http_referer"
#define HTTP_SBKD_ACCEPT "http_accept"
#define HTTP_SBKD_ACCEPT_LANGUAGE "http_accept_language"
#define HTTP_SBKD_ACCEPT_ENCODING "http_accept_encoding"
#define HTTP_SBKD_X_FORWARDED_FOR "http_x_forwarded_for"
#define HTTP_SBKD_REQUEST_CONNECTION "http_request_connection"
#define HTTP_SBKD_RESPONSE_VERSION "http_response_version"
#define HTTP_SBKD_CONTENT_TYPE "http_content_type"
#define HTTP_SBKD_CONTENT_DISPOSITION "http_content_disposition"
#define HTTP_SBKD_TRANSFER_ENCODING "http_transfer_encoding"
#define HTTP_SBKD_RESPONSE_CONNECTION "http_response_connection"
#define HTTP_SBKD_STATE "http_state"
#define HTTP_SBKD_STATUS_CODE "http_status_code"
#define HTTP_SBKD_REQUEST_HEADER_SIZE "http_request_header_size"
#define HTTP_SBKD_REQUEST_BODY_SIZE "http_request_body_size"
#define HTTP_SBKD_RESPONSE_HEADER_SIZE "http_response_header_size"
#define HTTP_SBKD_RESPONSE_BODY_SIZE "http_response_body_size"
#define HTTP_SBKD_SERVER_LATENCY "http_server_latency"
#define HTTP_SBKD_DOWNLOAD_LATENCY "http_download_latency"
#define HTTP_SBKD_RESPONSE_LATENCY "http_response_latency"

#endif /* __HTTP_ANALYZER_H__ */
