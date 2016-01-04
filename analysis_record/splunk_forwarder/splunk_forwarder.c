#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "util.h"
#include "log.h"
#include "http_client.h"
#include "splunk_forwarder.h"

int
initSplunkEventEntry (splunkEventEntryPtr entry, char *index, char *host, char *source,
                      char *sourcetype, char *time, char *event, int eventSize) {
    if (index)
        strncpy (entry->index, index, MAX_INDEX_LENGTH);

    if (host)
        strncpy (entry->host, host, MAX_HOST_LENGTH);

    if (source)
        strncpy (entry->source, source, MAX_SOURCE_LENGTH);

    if (sourcetype)
        strncpy (entry->sourcetype, sourcetype, MAX_SOURCETYPE_LENGTH);

    if (time)
        strncpy (entry->time, time, MAX_TIME_LENGTH);

    if (event) {
        if (entry->event == NULL || entry->eventSize < eventSize) {
            free (entry->event);
            entry->event = (char *) malloc (eventSize + 1);
            if (entry->event == NULL) {
                entry->eventSize = 0;
                return -1;
            }
        }

        memcpy (entry->event, event, eventSize);
        entry->event [eventSize] = 0;
        entry->eventSize = eventSize;
    }

    return 0;
}

splunkEventEntryPtr
newSplunkEventEntry (void) {
    splunkEventEntryPtr entry = (splunkEventEntryPtr) malloc (sizeof (splunkEventEntry));
    if (entry)
        memset (entry, 0, sizeof (splunkEventEntry));

    return entry;
}

void
freeSplunkEventEntry (splunkEventEntryPtr entry) {
    free (entry->event);
    free (entry);
}

static int
splunkEventEntrySize (splunkEventEntryPtr entry) {
    int size = 0;

    size += strlen (entry->index);
    size += strlen (entry->source);
    size += strlen (entry->sourcetype);
    size += strlen (entry->host);
    size += strlen (entry->time);
    size += strlen (entry->event);

    return size;
}

static char *
splunkEventEntry2Str (splunkEventEntryPtr entry, boolean *needFree) {
    int entrySize;
    char *data;
    char *pdata;
    int len;
    static __thread char entryBuf [4096];

    entrySize = splunkEventEntrySize (entry) + 128;
    if (entrySize <= sizeof (entryBuf)) {
        data = entryBuf;
        *needFree = False;
    } else {
        data = (char *) malloc (entrySize);
        if (data == NULL)
            return NULL;
        *needFree = True;
    }

    pdata = data;
    len  = snprintf (pdata, entrySize, "{");

    if (entry->index [0])
        len += snprintf (pdata + len, entrySize - len, "\"index\":\"%s\"", entry->index);

    if (entry->host [0])
        len += snprintf (pdata + len, entrySize - len, ",\"host\":\"%s\"", entry->host);

    if (entry->source [0])
        len += snprintf (pdata + len, entrySize - len, ",\"source\":\"%s\"", entry->source);

    if (entry->sourcetype [0])
        len += snprintf (pdata + len, entrySize - len, ",\"sourcetype\":\"%s\"", entry->sourcetype);

    if (entry->time [0])
        len += snprintf (pdata + len, entrySize - len, ",\"time\":\"%s\"", entry->time);

    if (entry->event [0])
        len += snprintf (pdata + len, entrySize - len, ",\"event\":%s", entry->event);

    snprintf (pdata + len, entrySize - len, "}");
    return data;
}

int
doWriteSplunkEventEntry (httpHandlerPtr handler, char *url, httpHeaderPtr header, splunkEventEntryPtr entry) {
    CURLcode res;
    boolean needFree;
    char *data;

    data = splunkEventEntry2Str (entry, &needFree);
    if (data == NULL) {
        LOGE ("Generate splunk event entry string error.\n");
        return -1;
    }

    res = postHttp (handler, url, header, data);
    if (res != CURLE_OK) {
        LOGE ("Post http error: %s\n", curl_easy_strerror (res));
        if (needFree)
            free (data);
        return -1;
    }

    if (needFree)
        free (data);
    return 0;
}

int
writeSplunkEventEntry (char *url, char *authToken, splunkEventEntryPtr entry) {
    int ret;
    char tmp [128] = {0};
    httpHandlerPtr handler;
    httpHeaderPtr header;

    handler = newHttp ();
    if (handler == NULL) {
        LOGE ("Create http handler error.\n");
        return -1;
    }

    header = newHttpHeader ();
    if (header == NULL) {
        LOGE ("Create http header error.\n");
        freeHttp (handler);
        return -1;
    }

    snprintf (tmp, sizeof (tmp), "Splunk %s", authToken);
    addHttpHeader (header, "Authorization", tmp);
    ret = doWriteSplunkEventEntry (handler, url, header, entry);

    freeHttpHeader (header);
    freeHttp (handler);
    return ret;
}
