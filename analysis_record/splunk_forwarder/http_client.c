#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "http_client.h"

httpHandlerPtr
newHttp (void) {
    curl_global_init (CURL_GLOBAL_ALL);
    CURL *curl = curl_easy_init ();

    httpHandlerPtr handler = (httpHandlerPtr) malloc (sizeof (httpHandler));
    if (handler == NULL)
        curl_easy_cleanup (curl);
    else
        handler->handler = curl;

    return handler;
}

void
freeHttp (httpHandlerPtr handler) {
    assert(handler != NULL && handler->handler != NULL);

    curl_easy_cleanup (handler->handler);
    curl_global_cleanup ();
    free (handler);
}

httpHeaderPtr
newHttpHeader (void) {
    httpHeaderPtr header = (httpHeaderPtr) malloc (sizeof (httpHeader));
    if (header)
        memset (header, 0, sizeof (httpHeader));
    return header;
}

void
freeHttpHeader (httpHeaderPtr header) {
    curl_slist_free_all (header->headers);
    free (header);
}

void
addHttpHeader (httpHeaderPtr header, char *key, char *value) {
    char buf [512] = {0};

    snprintf (buf, sizeof (buf), "%s: %s", key, value);
    header->headers = curl_slist_append (header->headers, buf);
}

size_t
postCallback (char *ptr, size_t size, size_t nmemb, void *userdata) {
    return size * nmemb;
}

CURLcode
postHttp (httpHandlerPtr handler, char *url, httpHeaderPtr header, char *data) {
    /* Ignore cert verification */
    if (!strncasecmp (url, "https://", 8)) {
        curl_easy_setopt (handler->handler, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt (handler->handler, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    curl_easy_setopt (handler->handler, CURLOPT_URL, url);
    curl_easy_setopt (handler->handler, CURLOPT_HTTPHEADER, header->headers);
    curl_easy_setopt (handler->handler, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt (handler->handler, CURLOPT_WRITEFUNCTION, postCallback);
    curl_easy_setopt (handler->handler, CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt (handler->handler, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt (handler->handler, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt (handler->handler, CURLOPT_TIMEOUT, 20);

    return curl_easy_perform (handler->handler);
}
