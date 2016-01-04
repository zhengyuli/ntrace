#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include "util.h"
#include "log.h"
#include "http_analyzer.h"

/* Current timestamp */
static __thread timeValPtr currTime;
/* Current session state indicator */
static __thread sessionState currSessionState;
/* Current http header type */
static __thread httpHeaderType currHeaderType;
/* Current http session detail */
static __thread httpSessionDetailPtr currSessionDetail;

static char *
getHttpBreakdownStateName (httpBreakdownState state) {
    switch (state) {
        case HTTP_BREAKDOWN_OK:
            return "HTTP_OK";

        case HTTP_BREAKDOWN_ERROR:
            return "HTTP_ERROR";

        case HTTP_BREAKDOWN_RESET_TYPE1:
            return "HTTP_RESET_TYPE1";

        case HTTP_BREAKDOWN_RESET_TYPE2:
            return "HTTP_RESET_TYPE2";

        case HTTP_BREAKDOWN_RESET_TYPE3:
            return "HTTP_RESET_TYPE3";

        case HTTP_BREAKDOWN_RESET_TYPE4:
            return "HTTP_RESET_TYPE4";

        default:
            return "HTTP_STATE_UNKNOWN";
    }
}

static httpSessionDetailNodePtr
newHttpSessionDetailNode (void);

static void
freeHttpSessionDetailNode (httpSessionDetailNodePtr hsdn);

static inline boolean
httpHeaderEqualWithLen (const char *hdr1, const char *hdr2, size_t hdr2Len) {
    if (strlen (hdr1) != hdr2Len)
        return False;

    if (!strncmp (hdr1, hdr2, hdr2Len))
        return True;
    else
        return False;
}

/* =====================================Http_parser callback===================================== */
/* Resquest callback */
static int
onReqMessageBegin (http_parser *parser) {
    httpSessionDetailNodePtr hsdn;

    hsdn = newHttpSessionDetailNode ();
    if (hsdn == NULL)
        LOGE ("NewHttpSessionDetailNode error.\n");
    else {
        hsdn->state = HTTP_REQUEST_HEADER_BEGIN;
        hsdn->reqTime = timeVal2MilliSecond (currTime);
        listAddTail (&hsdn->node, &currSessionDetail->head);
    }

    return 0;
}

static int
onReqUrl (http_parser *parser, const char *from, size_t length) {
    httpSessionDetailNodePtr currNode;

    currNode = listTailEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    currNode->method = strdup (http_method_str (parser->method));
    currNode->uri = strndup (from, length);
    if (currNode->uri == NULL)
        LOGE ("Get http request uri error.\n");

    return 0;
}

static int
onReqHeaderField (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    currNode = listTailEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    if (httpHeaderEqualWithLen (HTTP_HEADER_HOST_STRING, from, length))
        currHeaderType = HTTP_HEADER_HOST;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_USER_AGENT_STRING, from, length))
        currHeaderType = HTTP_HEADER_USER_AGENT;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_REFERER_STRING, from, length))
        currHeaderType = HTTP_HEADER_REFERER;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_ACCEPT_STRING, from, length))
        currHeaderType = HTTP_HEADER_ACCEPT;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_ACCEPT_LANGUAGE_STRING, from, length))
        currHeaderType = HTTP_HEADER_ACCEPT_LANGUAGE;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_ACCEPT_ENCODING_STRING, from, length))
        currHeaderType = HTTP_HEADER_ACCEPT_ENCODING;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_X_FORWARDED_FOR_STRING, from, length))
        currHeaderType = HTTP_HEADER_X_FORWARDED_FOR;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_CONNECTION_STRING, from, length))
        currHeaderType = HTTP_HEADER_CONNECTION;

    return 0;
}

static int
onReqHeaderValue (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    currNode = listTailEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    switch (currHeaderType) {
        case HTTP_HEADER_HOST:
            currNode->host = strndup (from, length);
            if (currNode->host == NULL)
                LOGE ("Get Host field error.\n");
            break;

        case HTTP_HEADER_USER_AGENT:
            currNode->userAgent = strndup (from, length);
            if (currNode->userAgent == NULL)
                LOGE ("Get User-Agent field error.\n");
            break;

        case HTTP_HEADER_REFERER:
            currNode->referer = strndup (from, length);
            if (currNode->referer == NULL)
                LOGE ("Get Referer field error.\n");
            break;

        case HTTP_HEADER_ACCEPT:
            currNode->accept = strndup (from, length);
            if (currNode->accept == NULL)
                LOGE ("Get Accept field error.\n");
            break;

        case HTTP_HEADER_ACCEPT_LANGUAGE:
            currNode->acceptLanguage = strndup (from, length);
            if (currNode->acceptLanguage == NULL)
                LOGE ("Get Accept-Language field error.\n");
            break;

        case HTTP_HEADER_ACCEPT_ENCODING:
            currNode->acceptEncoding = strndup (from, length);
            if (currNode->acceptEncoding == NULL)
                LOGE ("Get Accept-Encoding field error.\n");
            break;

        case HTTP_HEADER_X_FORWARDED_FOR:
            currNode->xForwardedFor = strndup (from, length);
            if (currNode->xForwardedFor == NULL)
                LOGE ("Get X-Forwarded-For field error.\n");
            break;

        case HTTP_HEADER_CONNECTION:
            currNode->reqConnection = strndup (from, length);
            if (currNode->reqConnection == NULL)
                LOGE ("Get Connection field error.\n");
            break;

        default:
            break;
    }
    currHeaderType = HTTP_HEADER_IGNORE;

    return 0;
}

static int
onReqHeadersComplete (http_parser *parser) {
    char verStr [HTTP_VERSION_LENGTH];
    httpSessionDetailNodePtr currNode;

    currNode = listTailEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_REQUEST_HEADER_COMPLETE;
    snprintf (verStr, sizeof (verStr), "HTTP/%d.%d", parser->http_major, parser->http_minor);
    currNode->reqVer = strdup (verStr);
    if (currNode->reqVer == NULL)
        LOGE ("Get request protocol version error.\n");
    currNode->reqHeaderSize = parser->nread;

    return 0;
}

static int
onReqBody (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    currNode = listTailEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_REQUEST_BODY_BEGIN;
    currNode->reqBodySize += length;

    return 0;
}

static int
onReqMessageComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    currNode = listTailEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_REQUEST_BODY_COMPLETE;

    return 0;
}

/* Response callback */
static int
onRespMessageBegin (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    currNode = listHeadEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_RESPONSE_HEADER_BEGIN;
    currNode->respTimeBegin = timeVal2MilliSecond (currTime);

    return 0;
}

static int
onRespUrl (http_parser *parser, const char *from, size_t length) {
    return 0;
}

static int
onRespHeaderField (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    currNode = listHeadEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    if (httpHeaderEqualWithLen (HTTP_HEADER_CONTENT_TYPE_STRING, from, length))
        currHeaderType = HTTP_HEADER_CONTENT_TYPE;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_CONTENT_DISPOSITION_STRING, from, length))
        currHeaderType = HTTP_HEADER_CONTENT_DISPOSITION;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_TRANSFER_ENCODING_STRING, from, length))
        currHeaderType = HTTP_HEADER_TRANSFER_ENCODING;
    else if (httpHeaderEqualWithLen (HTTP_HEADER_CONNECTION_STRING, from, length))
        currHeaderType = HTTP_HEADER_CONNECTION;

    return 0;
}

static int
onRespHeaderValue (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    currNode = listHeadEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    switch (currHeaderType) {
        case HTTP_HEADER_CONTENT_TYPE:
            currNode->contentType = strndup (from, length);
            if (currNode->contentType == NULL)
                LOGE ("Get Content-Type field error.\n");
            break;

        case HTTP_HEADER_CONTENT_DISPOSITION:
            currNode->contentDisposition = strndup (from, length);
            if (currNode->contentDisposition == NULL)
                LOGE ("Get Content-Disposition field error.\n");
            break;

        case HTTP_HEADER_TRANSFER_ENCODING:
            currNode->transferEncoding = strndup (from, length);
            if (currNode->transferEncoding == NULL)
                LOGE ("Get Transfer-Encoding field error.\n");
            break;

        case HTTP_HEADER_CONNECTION:
            currNode->respConnection = strndup (from, length);
            if (currNode->respConnection == NULL)
                LOGE ("Get Connection field error.\n");
            break;

        default:
            break;
    }
    currHeaderType = HTTP_HEADER_IGNORE;

    return 0;
}

static int
onRespHeadersComplete (http_parser *parser) {
    char verStr [HTTP_VERSION_LENGTH];
    httpSessionDetailNodePtr currNode;

    currNode = listHeadEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    snprintf (verStr, sizeof (verStr), "HTTP/%d.%d", parser->http_major, parser->http_minor);
    currNode->respVer = strdup (verStr);
    if (currNode->respVer == NULL)
        LOGE ("Get response protocol version error.\n");
    currNode->state = HTTP_RESPONSE_HEADER_COMPLETE;
    currNode->statusCode = parser->status_code;
    currNode->respHeaderSize = parser->nread;

    return 0;
}

static int
onRespBody (http_parser *parser, const char* from, size_t length) {
    httpSessionDetailNodePtr currNode;

    currNode = listHeadEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_RESPONSE_BODY_BEGIN;
    currNode->respBodySize += length;

    return 0;
}

static int
onRespMessageComplete (http_parser *parser) {
    httpSessionDetailNodePtr currNode;

    currNode = listHeadEntry (&currSessionDetail->head, httpSessionDetailNode, node);
    if (currNode == NULL)
        return 0;

    currNode->state = HTTP_RESPONSE_BODY_COMPLETE;
    currNode->respTimeEnd = timeVal2MilliSecond (currTime);
    currSessionState = SESSION_DONE;

    return 0;
}
/* =====================================Http_parser callback===================================== */

static int
initHttpAnalyzer (void) {
    return 0;
}

static void
destroyHttpAnalyzer (void) {
    return;
}

static httpSessionDetailNodePtr
newHttpSessionDetailNode (void) {
    httpSessionDetailNodePtr hsdn;

    hsdn = (httpSessionDetailNodePtr) malloc (sizeof (httpSessionDetailNode));
    if (hsdn == NULL)
        return NULL;

    hsdn->reqVer = NULL;
    hsdn->method = NULL;
    hsdn->uri = NULL;
    hsdn->host = NULL;
    hsdn->userAgent = NULL;
    hsdn->referer = NULL;
    hsdn->accept = NULL;
    hsdn->acceptLanguage = NULL;
    hsdn->acceptEncoding = NULL;
    hsdn->xForwardedFor = NULL;
    hsdn->reqConnection = NULL;
    hsdn->respVer = NULL;
    hsdn->contentType = NULL;
    hsdn->contentDisposition = NULL;
    hsdn->transferEncoding = NULL;
    hsdn->respConnection = NULL;
    hsdn->state = HTTP_INIT;
    hsdn->statusCode = 0;
    hsdn->reqTime = 0;
    hsdn->reqHeaderSize = 0;
    hsdn->reqBodySize = 0;
    hsdn->respTimeBegin = 0;
    hsdn->respHeaderSize = 0;
    hsdn->respBodySize = 0;
    hsdn->respTimeEnd = 0;
    initListHead (&hsdn->node);
    return hsdn;
}

static void
freeHttpSessionDetailNode (httpSessionDetailNodePtr hsdn) {
    free (hsdn->reqVer);
    hsdn->reqVer = NULL;
    free (hsdn->method);
    hsdn->method = NULL;
    free (hsdn->uri);
    hsdn->uri = NULL;
    free (hsdn->host);
    hsdn->host = NULL;
    free (hsdn->userAgent);
    hsdn->userAgent = NULL;
    free (hsdn->referer);
    hsdn->referer = NULL;
    free (hsdn->accept);
    hsdn->accept = NULL;
    free (hsdn->acceptLanguage);
    hsdn->acceptLanguage = NULL;
    free (hsdn->acceptEncoding);
    hsdn->acceptEncoding = NULL;
    free (hsdn->xForwardedFor);
    hsdn->xForwardedFor = NULL;
    free (hsdn->reqConnection);
    hsdn->reqConnection = NULL;
    free (hsdn->respVer);
    hsdn->respVer = NULL;
    free (hsdn->contentType);
    hsdn->contentType = NULL;
    free (hsdn->contentDisposition);
    hsdn->contentDisposition = NULL;
    free (hsdn->transferEncoding);
    hsdn->transferEncoding = NULL;
    free (hsdn->respConnection);
    hsdn->respConnection = NULL;

    free (hsdn);
}

static void *
newHttpSessionDetail (void) {
    httpSessionDetailPtr hsd;
    http_parser *reqParser;
    http_parser_settings *reqParserSettings;
    http_parser *resParser;
    http_parser_settings *resParserSettings;

    hsd = (httpSessionDetailPtr) malloc (sizeof (httpSessionDetail));
    if (hsd == NULL)
        return NULL;

    /* Init http request parser */
    reqParser = &hsd->reqParser;
    reqParserSettings = &hsd->reqParserSettings;
    memset (reqParserSettings, 0, sizeof (*reqParserSettings));
    reqParserSettings->on_message_begin = onReqMessageBegin;
    reqParserSettings->on_url = onReqUrl;
    reqParserSettings->on_header_field = onReqHeaderField;
    reqParserSettings->on_header_value = onReqHeaderValue;
    reqParserSettings->on_headers_complete = onReqHeadersComplete;
    reqParserSettings->on_body = onReqBody;
    reqParserSettings->on_message_complete = onReqMessageComplete;
    http_parser_init (reqParser, HTTP_REQUEST);

    /* Init http response parser */
    resParser = &hsd->resParser;
    resParserSettings = &hsd->resParserSettings;
    memset (resParserSettings, 0, sizeof (*resParserSettings));
    resParserSettings->on_message_begin = onRespMessageBegin;
    resParserSettings->on_url = onRespUrl;
    resParserSettings->on_header_field = onRespHeaderField;
    resParserSettings->on_header_value = onRespHeaderValue;
    resParserSettings->on_headers_complete = onRespHeadersComplete;
    resParserSettings->on_body = onRespBody;
    resParserSettings->on_message_complete = onRespMessageComplete;
    http_parser_init (resParser, HTTP_RESPONSE);
    initListHead (&hsd->head);
    return hsd;
}

static void
freeHttpSessionDetail (void *sd) {
    httpSessionDetailNodePtr item;
    listHeadPtr pos, npos;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;

    if (hsd == NULL)
        return;

    listForEachEntrySafe (item, pos, npos, &hsd->head, node) {
        listDel (&item->node);
        freeHttpSessionDetailNode (item);
    }

    free (sd);
}

static void *
newHttpSessionBreakdown (void) {
    httpSessionBreakdownPtr hsbd;

    hsbd = (httpSessionBreakdownPtr) malloc (sizeof (httpSessionBreakdown));
    if (hsbd == NULL)
        return NULL;

    hsbd->reqVer = NULL;
    hsbd->method = NULL;
    hsbd->uri = NULL;
    hsbd->host = NULL;
    hsbd->userAgent = NULL;
    hsbd->referer = NULL;
    hsbd->accept = NULL;
    hsbd->acceptLanguage = NULL;
    hsbd->acceptEncoding = NULL;
    hsbd->xForwardedFor = NULL;
    hsbd->reqConnection = NULL;
    hsbd->respVer = NULL;
    hsbd->contentType = NULL;
    hsbd->contentDisposition = NULL;
    hsbd->transferEncoding = NULL;
    hsbd->respConnection = NULL;
    hsbd->state = HTTP_BREAKDOWN_ERROR;
    hsbd->statusCode = 0;
    hsbd->reqHeaderSize = 0;
    hsbd->reqBodySize = 0;
    hsbd->respHeaderSize = 0;
    hsbd->respBodySize = 0;
    hsbd->serverLatency = 0;
    hsbd->downloadLatency = 0;
    hsbd->respLatency = 0;
    return hsbd;
}

static void
freeHttpSessionBreakdown (void *sbd) {
    httpSessionBreakdownPtr hsbd = (httpSessionBreakdownPtr) sbd;

    if (hsbd == NULL)
        return;

    free (hsbd->reqVer);
    hsbd->reqVer = NULL;
    free (hsbd->method);
    hsbd->method = NULL;
    free (hsbd->uri);
    hsbd->uri = NULL;
    free (hsbd->host);
    hsbd->host = NULL;
    free (hsbd->userAgent);
    hsbd->userAgent = NULL;
    free (hsbd->referer);
    hsbd->referer = NULL;
    free (hsbd->accept);
    hsbd->accept = NULL;
    free (hsbd->acceptLanguage);
    hsbd->acceptLanguage = NULL;
    free (hsbd->acceptEncoding);
    hsbd->acceptEncoding = NULL;
    free (hsbd->xForwardedFor);
    hsbd->xForwardedFor = NULL;
    free (hsbd->reqConnection);
    hsbd->reqConnection = NULL;
    free (hsbd->respVer);
    hsbd->respVer = NULL;
    free (hsbd->contentType);
    hsbd->contentType = NULL;
    free (hsbd->contentDisposition);
    hsbd->contentDisposition = NULL;
    free (hsbd->transferEncoding);
    hsbd->transferEncoding = NULL;
    free (hsbd->respConnection);
    hsbd->respConnection = NULL;

    free (sbd);
}

static inline httpBreakdownState
genHttpBreakdownState (u_short statusCode) {
    u_short st = statusCode / 100;
    if (st == 1 || st == 2 || st == 3)
        return HTTP_BREAKDOWN_OK;
    else
        return HTTP_BREAKDOWN_ERROR;
}

static int
generateHttpSessionBreakdown (void *sd, void *sbd) {
    httpSessionDetailNodePtr hsdn;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;
    httpSessionBreakdownPtr hsbd = (httpSessionBreakdownPtr) sbd;

    hsdn = listHeadEntry (&hsd->head, httpSessionDetailNode, node);
    if (hsdn == NULL) {
        LOGE ("Generate http session breakdown error.\n");
        return -1;
    }

    /* Remove from httpSessionDetailNode list */
    listDel (&hsdn->node);
    if (hsdn->reqVer) {
        hsbd->reqVer = strdup (hsdn->reqVer);
        if (hsbd->reqVer == NULL) {
            LOGE ("Strdup httpSessionBreakdown reqVer error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->method) {
        hsbd->method = strdup (hsdn->method);
        if (hsbd->method == NULL) {
            LOGE ("Strdup httpSessionBreakdown method error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->uri) {
        hsbd->uri = strdup (hsdn->uri);
        if (hsbd->uri == NULL) {
            LOGE ("Strdup httpSessionBreakdown request uri error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->host) {
        hsbd->host = strdup (hsdn->host);
        if (hsbd->host == NULL) {
            LOGE ("Strdup http host error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->userAgent) {
        hsbd->userAgent = strdup (hsdn->userAgent);
        if (hsbd->userAgent == NULL) {
            LOGE ("Strdup http User-Agent error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->referer) {
        hsbd->referer = strdup (hsdn->referer);
        if (hsbd->referer == NULL) {
            LOGE ("Strdup httpSessionBreakdown referer url error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->accept) {
        hsbd->accept = strdup (hsdn->accept);
        if (hsbd->accept == NULL) {
            LOGE ("Strdup httpSessionBreakdown accept error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->acceptLanguage) {
        hsbd->acceptLanguage = strdup (hsdn->acceptLanguage);
        if (hsbd->acceptLanguage == NULL) {
            LOGE ("Strdup httpSessionBreakdown acceptLanguage error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->acceptEncoding) {
        hsbd->acceptEncoding = strdup (hsdn->acceptEncoding);
        if (hsbd->acceptEncoding == NULL) {
            LOGE ("Strdup httpSessionBreakdown acceptEncoding error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->xForwardedFor) {
        hsbd->xForwardedFor = strdup (hsdn->xForwardedFor);
        if (hsbd->xForwardedFor == NULL) {
            LOGE ("Strdup httpSessionBreakdown xForwardedFor error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->reqConnection) {
        hsbd->reqConnection = strdup (hsdn->reqConnection);
        if (hsbd->reqConnection == NULL) {
            LOGE ("Strdup httpSessionBreakdown reqConnection error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->respVer) {
        hsbd->respVer = strdup (hsdn->respVer);
        if (hsbd->respVer == NULL) {
            LOGE ("Strdup httpSessionBreakdown respVer error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->contentType) {
        hsbd->contentType = strdup (hsdn->contentType);
        if (hsbd->contentType == NULL) {
            LOGE ("Strdup httpSessionBreakdown Content-Type error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->contentDisposition) {
        hsbd->contentDisposition = strdup (hsdn->contentDisposition);
        if (hsbd->contentDisposition == NULL) {
            LOGE ("Strdup httpSessionBreakdown contentDisposition error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->transferEncoding) {
        hsbd->transferEncoding = strdup (hsdn->transferEncoding);
        if (hsbd->transferEncoding == NULL) {
            LOGE ("Strdup httpSessionBreakdown transferEncoding error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    if (hsdn->respConnection) {
        hsbd->respConnection = strdup (hsdn->respConnection);
        if (hsbd->respConnection == NULL) {
            LOGE ("Strdup httpSessionBreakdown respConnection error: %s.\n", strerror (errno));
            freeHttpSessionDetailNode (hsdn);
            return -1;
        }
    }

    switch (hsdn->state) {
        case HTTP_RESPONSE_BODY_COMPLETE:
            hsbd->state = genHttpBreakdownState (hsdn->statusCode);
            hsbd->statusCode = hsdn->statusCode;
            hsbd->reqHeaderSize = hsdn->reqHeaderSize;
            hsbd->reqBodySize = hsdn->reqBodySize;
            hsbd->respHeaderSize = hsdn->respHeaderSize;
            hsbd->respBodySize = hsdn->respBodySize;
            hsbd->serverLatency = (u_int) (hsdn->respTimeBegin - hsdn->reqTime);
            hsbd->downloadLatency = (u_int) (hsdn->respTimeEnd - hsdn->respTimeBegin);
            hsbd->respLatency = (u_int) (hsdn->respTimeEnd - hsdn->reqTime);
            break;

        case HTTP_RESET_TYPE1:
        case HTTP_RESET_TYPE2:
            if (hsdn->state == HTTP_RESET_TYPE1)
                hsbd->state = HTTP_BREAKDOWN_RESET_TYPE1;
            else
                hsbd->state = HTTP_BREAKDOWN_RESET_TYPE2;
            hsbd->statusCode = hsdn->statusCode;
            hsbd->reqHeaderSize = hsdn->reqHeaderSize;
            hsbd->reqBodySize = hsdn->reqBodySize;
            hsbd->respHeaderSize = 0;
            hsbd->respBodySize = 0;
            hsbd->serverLatency = 0;
            hsbd->downloadLatency = 0;
            hsbd->respLatency = 0;
            break;

        case HTTP_RESET_TYPE3:
            hsbd->state = HTTP_BREAKDOWN_RESET_TYPE3;
            hsbd->statusCode = hsdn->statusCode;
            hsbd->reqHeaderSize = hsdn->reqHeaderSize;
            hsbd->reqBodySize = hsdn->reqBodySize;
            hsbd->respHeaderSize = hsdn->respHeaderSize;
            hsbd->respBodySize = hsdn->respBodySize;
            hsbd->serverLatency = (u_int) (hsdn->respTimeBegin - hsdn->reqTime);
            hsbd->downloadLatency = 0;
            hsbd->respLatency = (u_int) (hsdn->respTimeBegin - hsdn->reqTime);
            break;

        case HTTP_RESET_TYPE4:
            hsbd->state = HTTP_BREAKDOWN_RESET_TYPE4;
            hsbd->statusCode = 0;
            hsbd->reqHeaderSize = 0;
            hsbd->reqBodySize = 0;
            hsbd->respHeaderSize = 0;
            hsbd->respBodySize = 0;
            hsbd->serverLatency = 0;
            hsbd->downloadLatency = 0;
            hsbd->respLatency = 0;
            break;

        default:
            LOGE ("Wrong http state for breakdown.\n");
            freeHttpSessionDetailNode (hsdn);
            return -1;
    }

    /* Free session detail node */
    freeHttpSessionDetailNode (hsdn);
    return 0;
}

static void
httpSessionBreakdown2Json (json_t *root, void *sd, void *sbd) {
    char buf [1024];
    httpSessionBreakdownPtr hsbd = (httpSessionBreakdownPtr) sbd;

    if (hsbd->state != HTTP_BREAKDOWN_RESET_TYPE4) {
        /* Http request version */
        if (hsbd->reqVer)
            json_object_set_new (root, HTTP_SBKD_REQUEST_VERSION,
                                 json_string (hsbd->reqVer));

        /* Http request method */
        if (hsbd->method)
            json_object_set_new (root, HTTP_SBKD_METHOD,
                                 json_string (hsbd->method));

        /* Http request uri */
        if (hsbd->uri)
            json_object_set_new (root, HTTP_SBKD_URI,
                                 json_string (hsbd->uri));

        /* Http request host */
        if (hsbd->host)
            json_object_set_new (root, HTTP_SBKD_HOST,
                                 json_string (hsbd->host));

        /* Http request line */
        snprintf (buf, sizeof (buf), "%s http://%s%s",
                  hsbd->method, hsbd->host, hsbd->uri);

        /* Http request user agent */
        if (hsbd->userAgent)
            json_object_set_new (root, HTTP_SBKD_USER_AGENT,
                                 json_string (hsbd->userAgent));

        /* Http referer url */
        if (hsbd->referer)
            json_object_set_new (root, HTTP_SBKD_REFERER,
                                 json_string (hsbd->referer));

        /* Http request accept source */
        if (hsbd->accept)
            json_object_set_new (root, HTTP_SBKD_ACCEPT,
                                 json_string (hsbd->accept));

        /* Http request accept Language */
        if (hsbd->acceptLanguage)
            json_object_set_new (root, HTTP_SBKD_ACCEPT_LANGUAGE,
                                 json_string (hsbd->acceptLanguage));

        /* Http request accept encoding */
        if (hsbd->acceptEncoding)
            json_object_set_new (root, HTTP_SBKD_ACCEPT_ENCODING,
                                 json_string (hsbd->acceptEncoding));

        /* Http request X-Forwarded-For */
        if (hsbd->xForwardedFor)
            json_object_set_new (root, HTTP_SBKD_X_FORWARDED_FOR,
                                 json_string (hsbd->xForwardedFor));

        /* Http request connection type */
        if (hsbd->reqConnection)
            json_object_set_new (root, HTTP_SBKD_REQUEST_CONNECTION,
                                 json_string (hsbd->reqConnection));

        /* Http response version */
        if (hsbd->respVer)
            json_object_set_new (root, HTTP_SBKD_RESPONSE_VERSION,
                                 json_string (hsbd->respVer));

        /* Http response connection type */
        if (hsbd->contentType)
            json_object_set_new (root, HTTP_SBKD_CONTENT_TYPE,
                                 json_string (hsbd->contentType));

        /* Http response content Disposition */
        if (hsbd->contentDisposition)
            json_object_set_new (root, HTTP_SBKD_CONTENT_DISPOSITION,
                                 json_string (hsbd->contentDisposition));

        /* Http response transfer Encoding */
        if (hsbd->transferEncoding)
            json_object_set_new (root, HTTP_SBKD_TRANSFER_ENCODING,
                                 json_string (hsbd->transferEncoding));

        /* Http response connection type */
        if (hsbd->respConnection)
            json_object_set_new (root, HTTP_SBKD_RESPONSE_CONNECTION,
                                 json_string (hsbd->respConnection));

        /* Http state */
        json_object_set_new (root, HTTP_SBKD_STATE,
                             json_string (getHttpBreakdownStateName (hsbd->state)));
        /* Http status code */
        json_object_set_new (root, HTTP_SBKD_STATUS_CODE,
                             json_integer (hsbd->statusCode));
        /* Http request header size */
        json_object_set_new (root, HTTP_SBKD_REQUEST_HEADER_SIZE,
                             json_integer (hsbd->reqHeaderSize));
        /* Http request body size */
        json_object_set_new (root, HTTP_SBKD_REQUEST_BODY_SIZE,
                             json_integer (hsbd->reqBodySize));
        /* Http response header size */
        json_object_set_new (root, HTTP_SBKD_RESPONSE_HEADER_SIZE,
                             json_integer (hsbd->respHeaderSize));
        /* Http response body size */
        json_object_set_new (root, HTTP_SBKD_RESPONSE_BODY_SIZE,
                             json_integer (hsbd->respBodySize));
        /* Http server latency */
        json_object_set_new (root, HTTP_SBKD_SERVER_LATENCY,
                             json_integer (hsbd->serverLatency));
        /* Http download latency */
        json_object_set_new (root, HTTP_SBKD_DOWNLOAD_LATENCY,
                             json_integer (hsbd->downloadLatency));
        /* Http response latency */
        json_object_set_new (root, HTTP_SBKD_RESPONSE_LATENCY,
                             json_integer (hsbd->respLatency));
    }
}

static void
httpSessionProcessEstb (timeValPtr tm, void *sd) {
    return;
}

static void
httpSessionProcessUrgData (streamDirection direction, char urgData,
                           timeValPtr tm, void *sd) {
    return;
}

static u_int
httpSessionProcessData (streamDirection direction, u_char *data, u_int dataLen,
                        timeValPtr tm, void *sd, sessionState *state) {
    u_int parseCount;

    currTime = tm;
    currSessionState = SESSION_ACTIVE;
    currHeaderType = HTTP_HEADER_IGNORE;
    currSessionDetail = (httpSessionDetailPtr) sd;

    if (direction == STREAM_FROM_CLIENT)
        parseCount = http_parser_execute (&currSessionDetail->reqParser,
                                          &currSessionDetail->reqParserSettings,
                                          (const char *) data, dataLen);
    else
        parseCount = http_parser_execute (&currSessionDetail->resParser,
                                          &currSessionDetail->resParserSettings,
                                          (const char *) data, dataLen);

    *state = currSessionState;
    return parseCount;
}

static void
httpSessionProcessReset (streamDirection direction, timeValPtr tm, void *sd) {
    httpSessionDetailNodePtr currNode;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;

    currNode = listHeadEntry (&hsd->head, httpSessionDetailNode, node);
    if (currNode) {
        if (currNode->state == HTTP_REQUEST_HEADER_BEGIN ||
            currNode->state == HTTP_REQUEST_HEADER_COMPLETE ||
            currNode->state == HTTP_REQUEST_BODY_BEGIN)
            currNode->state = HTTP_RESET_TYPE1;
        else if (currNode->state == HTTP_REQUEST_BODY_COMPLETE)
            currNode->state = HTTP_RESET_TYPE2;
        else if (currNode->state == HTTP_RESPONSE_HEADER_BEGIN ||
                 currNode->state == HTTP_RESPONSE_HEADER_COMPLETE ||
                 currNode->state == HTTP_RESPONSE_BODY_BEGIN)
            currNode->state = HTTP_RESET_TYPE3;
    } else {
        /*
         * For http reset without request, we need to create a fake http session
         * detail node and set session detail node state to HTTP_RESET_TYPE4.
         */
        currNode = newHttpSessionDetailNode ();
        if (currNode == NULL)
            LOGE ("NewHttpSessionDetailNode error.\n");
        else {
            currNode->state = HTTP_RESET_TYPE4;
            listAddTail (&currNode->node, &hsd->head);
        }
    }
}

static void
httpSessionProcessFin (streamDirection direction, timeValPtr tm, void *sd,
                       sessionState *state) {
    httpSessionDetailNodePtr currNode;
    httpSessionDetailPtr hsd = (httpSessionDetailPtr) sd;

    if (direction == STREAM_FROM_SERVER) {
        currNode = listHeadEntry (&hsd->head, httpSessionDetailNode, node);
        if (currNode == NULL)
            return;

        if (currNode->state == HTTP_RESPONSE_BODY_BEGIN) {
            currNode->state = HTTP_RESPONSE_BODY_COMPLETE;
            currNode->respTimeEnd = timeVal2MilliSecond (tm);
            *state = SESSION_DONE;
        }
    }
}

protoAnalyzer httpAnalyzer;

static char *
httpSessionProcessProtoDetect (streamDirection direction, timeValPtr tm,
                               u_char *data, u_int dataLen) {
    u_int i;
    u_int preLen;

    if (direction == STREAM_FROM_CLIENT) {
        /* Normal */
        if (dataLen >= 7 && memcmp ("DELETE ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 4 && memcmp ("GET ", data, 4) == 0)
            preLen = 4;
        else if (dataLen >= 5 && memcmp ("HEAD ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 5 && memcmp ("POST ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 4 && memcmp ("PUT ", data, 4) == 0)
            preLen = 4;
        /* Pathological */
        else if (dataLen >= 8 && memcmp ("CONNECT ", data, 8) == 0)
            preLen = 8;
        else if (dataLen >= 8 && memcmp ("OPTIONS ", data, 8) == 0)
            preLen = 8;
        else if (dataLen >= 6 && memcmp ("TRACE ", data, 6) == 0)
            preLen = 6;
        /* Webdav */
        else if (dataLen >= 5 && memcmp ("COPY ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 5 && memcmp ("LOCK ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 6 && memcmp ("MKCOL ", data, 6) == 0)
            preLen = 6;
        else if (dataLen >= 5 && memcmp ("MOVE ", data, 5) == 0)
            preLen = 5;
        else if (dataLen >= 9 && memcmp ("PROPFIND ", data, 9) == 0)
            preLen = 9;
        else if (dataLen >= 10 && memcmp ("PROPPATCH ", data, 10) == 0)
            preLen = 7;
        else if (dataLen >= 7 && memcmp ("SEARCH ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 7 && memcmp ("UNLOCK ", data, 7) == 0)
            preLen = 7;
        /* Subversion */
        else if (dataLen >= 7 && memcmp ("REPORT ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 11 && memcmp ("MKACTIVITY ", data, 11) == 0)
            preLen = 11;
        else if (dataLen >= 9 && memcmp ("CHECKOUT ", data, 9) == 0)
            preLen = 9;
        else if (dataLen >= 6 && memcmp ("MERGE ", data, 6) == 0)
            preLen = 6;
        /* Upnp */
        else if (dataLen >= 8 && memcmp ("MSEARCH ", data, 8) == 0)
            preLen = 8;
        else if (dataLen >= 7 && memcmp ("NOTIFY ", data, 7) == 0)
            preLen = 7;
        else if (dataLen >= 10 && memcmp ("SUBSCRIBE ", data, 10) == 0)
            preLen = 12;
        else if (dataLen >= 12 && memcmp ("UNSUBSCRIBE ", data, 12) == 0)
            preLen = 12;
        /* RFC-5789 */
        else if (dataLen >= 6 && memcmp ("PATCH ", data, 6) == 0)
            preLen = 6;
        else if (dataLen >= 6 && memcmp ("PURGE ", data, 6) == 0)
            preLen = 6;
        else
            preLen = 0;

        if (preLen) {
            /* Found the first line end flag '\r\n' */
            for (i = preLen; i < dataLen - 1; i++) {
                if (data [i] == '\r' &&
                    data [i + 1] == '\n' &&
                    (memcmp ("HTTP/1.0", data + i - 8, 8) == 0 ||
                     memcmp ("HTTP/1.1", data + i - 8, 8) == 0)) {
                    return httpAnalyzer.proto;
                }
            }
        }
    } else {
        if (dataLen >= 8 &&
            (memcmp ("HTTP/1.0", data, 8) == 0 ||
             memcmp ("HTTP/1.1", data, 8) == 0))
            return httpAnalyzer.proto;
    }

    return NULL;
}

protoAnalyzer httpAnalyzer = {
    .proto = "HTTP",
    .initProtoAnalyzer = initHttpAnalyzer,
    .destroyProtoAnalyzer = destroyHttpAnalyzer,
    .newSessionDetail = newHttpSessionDetail,
    .freeSessionDetail = freeHttpSessionDetail,
    .newSessionBreakdown = newHttpSessionBreakdown,
    .freeSessionBreakdown = freeHttpSessionBreakdown,
    .generateSessionBreakdown = generateHttpSessionBreakdown,
    .sessionBreakdown2Json = httpSessionBreakdown2Json,
    .sessionProcessEstb = httpSessionProcessEstb,
    .sessionProcessUrgData = httpSessionProcessUrgData,
    .sessionProcessData = httpSessionProcessData,
    .sessionProcessReset = httpSessionProcessReset,
    .sessionProcessFin = httpSessionProcessFin,
    .sessionProcessProtoDetect = httpSessionProcessProtoDetect
};
