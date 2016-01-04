#ifndef __SPLUNK_FORWARDER_H__
#define __SPLUNK_FORWARDER_H__

#include "http_client.h"

#define MAX_INDEX_LENGTH 128
#define MAX_HOST_LENGTH 128
#define MAX_SOURCE_LENGTH 128
#define MAX_SOURCETYPE_LENGTH 128
#define MAX_TIME_LENGTH 64

typedef struct _splunkEventEntry splunkEventEntry;
typedef splunkEventEntry *splunkEventEntryPtr;

struct _splunkEventEntry {
    char index [MAX_INDEX_LENGTH];
    char host [MAX_HOST_LENGTH];
    char source [MAX_SOURCE_LENGTH];
    char sourcetype [MAX_SOURCETYPE_LENGTH];
    char time [MAX_TIME_LENGTH];
    char *event;
    int eventSize;
};

/*========================Interfaces definition============================*/
int
initSplunkEventEntry (splunkEventEntryPtr entry, char *index, char *host, char *source,
                      char *sourcetype, char *time, char *event, int eventSize);
splunkEventEntryPtr
newSplunkEventEntry (void);
void
freeSplunkEventEntry (splunkEventEntryPtr entry);
int
doWriteSplunkEventEntry (httpHandlerPtr handler, char *url, httpHeaderPtr header, splunkEventEntryPtr entry);
int
writeSplunkEventEntry (char *url, char *authToken, splunkEventEntryPtr entry);
/*=======================Interfaces definition end=========================*/

#endif /* __SPLUNK_FORWARDER_H__ */
