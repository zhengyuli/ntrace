#ifndef __HTTP_CLIENT_H__
#define __HTTP_CLIENT_H__

#include <curl/curl.h>

typedef struct _httpHandler httpHandler;
typedef httpHandler *httpHandlerPtr;

struct _httpHandler {
    CURL *handler;
};

typedef struct _httpHeader httpHeader;
typedef httpHeader *httpHeaderPtr;

struct _httpHeader {
    struct curl_slist *headers;
};

/*========================Interfaces definition============================*/
httpHandlerPtr
newHttp (void);
void
freeHttp (httpHandlerPtr handler);
httpHeaderPtr
newHttpHeader (void);
void
freeHttpHeader (httpHeaderPtr header);
void
addHttpHeader (httpHeaderPtr header, char *key, char *value);
CURLcode
postHttp (httpHandlerPtr handler, char *url, httpHeaderPtr header, char *data);
/*=======================Interfaces definition end=========================*/

#endif /* __HTTP_CLIENT_H__ */
