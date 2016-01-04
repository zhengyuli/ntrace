#include <error.h>
#include <string.h>
#include <pthread.h>
#include "util.h"
#include "log.h"
#include "ownership_manager.h"

#define OWNERSHIP_MAP_SIZE 128

/* Ownership instance num */
static u_int ownershipInstanceNum = 0;
/* Ownership instance list */
static listHead ownershipInstanceList;

/* Master ownership map rwlock */
static pthread_rwlock_t ownershipMapMasterRWLock;
/* Master ownership map */
static ownershipPtr *ownershipMapMaster;
/* Slave ownership map */
static ownershipPtr *ownershipMapSlave;

static void
swapOwnershipMap (void) {
    ownershipPtr *tmp;

    tmp = ownershipMapMaster;
    pthread_rwlock_wrlock (&ownershipMapMasterRWLock);
    ownershipMapMaster = ownershipMapSlave;
    pthread_rwlock_unlock (&ownershipMapMasterRWLock);
    ownershipMapSlave = tmp;
}

/**
 * @brief Get ownership packet dispatch sock.
 *
 * @param hash -- packet hash
 *
 * @return pktDispatchSock of ownership
 */
inline void *
getOwnershipPktDispatchSock (u_int hash) {
    void *sock;

    pthread_rwlock_rdlock (&ownershipMapMasterRWLock);
    sock = ownershipMapMaster [hash % OWNERSHIP_MAP_SIZE]->pktDispatchSock;
    pthread_rwlock_unlock (&ownershipMapMasterRWLock);

    return sock;
}

int
initOwnershipManager (void) {
    int ret;
    u_int i;
    ownershipPtr localOwnership;

    initListHead (&ownershipInstanceList);

    localOwnership = newLocalOwnership ();
    if (localOwnership == NULL) {
        LOGE ("Create localOwnership error.\n");
        return -1;
    }

    ret = pthread_rwlock_init (&ownershipMapMasterRWLock, NULL);
    if (ret) {
        LOGE ("Init ownershipMapMasterRWLock error.\n");
        goto freeLocalOwnershipInstance;
    }

    ownershipMapMaster = (ownershipPtr *) malloc (sizeof (ownershipPtr) * OWNERSHIP_MAP_SIZE);
    if (ownershipMapMaster == NULL) {
        LOGE ("Alloc ownershipMapMaster error.\n");
        goto destroyOwnershipMapMasterRWLock;
    }

    ownershipMapSlave = (ownershipPtr *) malloc (sizeof (ownershipPtr) * OWNERSHIP_MAP_SIZE);
    if (ownershipMapSlave == NULL) {
        LOGE ("Alloc ownershipMapSlave error.\n");
        goto freeOwnershipMapMaster;
    }

    /* Init master/slave ownership map */
    for (i = 0; i < OWNERSHIP_MAP_SIZE; i++) {
        ownershipMapMaster [i] = localOwnership;
        ownershipMapSlave [i] = localOwnership;
    }

    listAdd (&localOwnership->node, &ownershipInstanceList);
    ownershipInstanceNum = 1;

    return 0;

freeOwnershipMapMaster:
    free (ownershipMapMaster);
destroyOwnershipMapMasterRWLock:
    pthread_rwlock_destroy (&ownershipMapMasterRWLock);
freeLocalOwnershipInstance:
    freeOwnership (localOwnership);
    return -1;
}

void
destroyOwnershipManager (void) {
    ownershipPtr entry;
    listHeadPtr pos, npos;

    pthread_rwlock_destroy (&ownershipMapMasterRWLock);
    free (ownershipMapMaster);
    free (ownershipMapSlave);

    listForEachEntrySafe (entry, pos, npos, &ownershipInstanceList, node) {
        listDel (&entry->node);
        freeOwnership (entry);
    }
    ownershipInstanceNum = 0;
}
