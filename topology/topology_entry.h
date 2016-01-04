#ifndef __TOPOLOGY_ENTRY_H__
#define __TOPOLOGY_ENTRY_H__

#include <stdlib.h>
#include <jansson.h>
#include "util.h"

typedef struct _topologyEntry topologyEntry;
typedef topologyEntry *topologyEntryPtr;

struct _topologyEntry {
    char *srcIp;
    char *destIp;
};

#define TOPOLOGY_ENTRY_SOURCE_IP "source_ip"
#define TOPOLOGY_ENTRY_DEST_IP "dest_ip"

/*========================Interfaces definition============================*/
topologyEntryPtr
newTopologyEntry (char *srcIp, char *destIp);
void
freeTopologyEntry (topologyEntryPtr entry);
void
freeTopologyEntryForHash (void *data);
json_t *
topologyEntry2Json (topologyEntryPtr entry);
char *
topologyEntryAnalysisRecord (timeValPtr tm, char *srcIp, char *destIp);
/*=======================Interfaces definition end=========================*/

#endif /* __TOPOLOGY_ENTRY_H__ */
