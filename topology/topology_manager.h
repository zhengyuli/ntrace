#ifndef __TOPOLOGY_MANAGER_H__
#define __TOPOLOGY_MANAGER_H__

#include <jansson.h>
#include "topology_entry.h"

/*========================Interfaces definition============================*/
topologyEntryPtr
getTopologyEntry (char *srcIp, char *destIp);
json_t *
getJsonFromTopologyEntries (void);
int
addTopologyEntry (char *srcIp, char *destIp);
int
initTopologyManager (void);
void
destroyTopologyManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __TOPOLOGY_MANAGER_H__ */
