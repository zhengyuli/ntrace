#ifndef __OWNERSHIP_H__
#define __OWNERSHIP_H__

#include <stdlib.h>
#include <jansson.h>
#include <czmq.h>
#include "list.h"

typedef enum {
    OWNERSHIP_TYPE_LOCAL,
    OWNERSHIP_TYPE_REMOTE
} ownershipType;

typedef struct _ownership ownership;
typedef ownership *ownershipPtr;

struct _ownership {
    ownershipType type;
    char *ip;
    u_int cpuCores;
    u_int totalMem;
    u_int freeMem;
    zctx_t *zmqCtxt;
    void *pktDispatchSock;
    listHead node;
};

/*========================Interfaces definition============================*/
ownershipPtr
newOwnership (ownershipType type, char *ip,
              u_int cpuCores, u_int totalMem, u_int freeMem);
ownershipPtr
newLocalOwnership (void);
void
freeOwnership (ownershipPtr self);
/*=======================Interfaces definition end=========================*/

#endif /* __OWNERSHIP_H__ */
