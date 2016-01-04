#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <pthread.h>
#include "log.h"
#include "hash.h"
#include "topology_entry.h"
#include "topology_manager.h"

/* Topology entries hash table rwlock */
static pthread_rwlock_t topologyEntriesHashTableRWLock;
/* Topology entries hash table */
static hashTablePtr topologyEntriesHashTable = NULL;

/**
 * @brief Get topology entry from topology entries hash table.
 *
 * @param srcIp -- source ip
 * @param destIp -- dest ip
 *
 * @return topology entry if success, else NULL
 */
topologyEntryPtr
getTopologyEntry (char *srcIp, char *destIp) {
    char key [32];
    topologyEntryPtr entry;

    snprintf (key, sizeof (key), "%s:%s", srcIp, destIp);
    pthread_rwlock_rdlock (&topologyEntriesHashTableRWLock);
    entry = (topologyEntryPtr) hashLookup (topologyEntriesHashTable, key);
    pthread_rwlock_unlock (&topologyEntriesHashTableRWLock);

    return entry;
}

static int
getJsonForEachTopologyEntry (void *data, void *args) {
    json_t *root = (json_t *) args;
    json_t *entry;

    entry = topologyEntry2Json ((topologyEntryPtr) data);
    if (entry == NULL) {
        LOGE ("Get json from topologyEntry error.\n");
        return -1;
    }

    json_array_append_new (root, entry);
    return 0;
}

/* Get json from topology entries */
json_t *
getJsonFromTopologyEntries (void) {
    int ret;
    json_t *root;

    root = json_array ();
    if (root == NULL) {
        LOGE ("Create json array object error.\n");
        return NULL;
    }

    pthread_rwlock_rdlock (&topologyEntriesHashTableRWLock);
    ret = hashLoopDo (topologyEntriesHashTable,
                      getJsonForEachTopologyEntry,
                      root);
    pthread_rwlock_unlock (&topologyEntriesHashTableRWLock);

    if (ret < 0) {
        LOGE ("Get topologyEntries json from each topologyEntry error.\n");
        json_object_clear (root);
        return NULL;
    }

    return root;
}

/**
 * @brief Add topology entry to topology entries hash table.
 *
 * @param srcIp -- source ip
 * @param destIp -- dest ip
 *
 * @return 0 if success, else -1
 */
int
addTopologyEntry (char *srcIp, char *destIp) {
    int ret;
    topologyEntryPtr entry;
    char key [32];

    entry = newTopologyEntry (srcIp, destIp);
    if (entry == NULL) {
        LOGE ("Create topology entry %s:%s error\n", srcIp, destIp);
        return -1;
    }
    snprintf (key, sizeof (key), "%s:%s", srcIp, destIp);
    pthread_rwlock_wrlock (&topologyEntriesHashTableRWLock);
    ret = hashInsert (topologyEntriesHashTable, key, entry, freeTopologyEntryForHash);
    pthread_rwlock_unlock (&topologyEntriesHashTableRWLock);
    if (ret < 0) {
        LOGE ("Insert topology entry %s error\n", key);
        return -1;
    }

    return 0;
}

/* Init topology manager */
int
initTopologyManager (void) {
    int ret;

    ret = pthread_rwlock_init (&topologyEntriesHashTableRWLock, NULL);
    if (ret) {
        LOGE ("Init topologyEntriesHashTableRWLock error.\n");
        return -1;
    }

    topologyEntriesHashTable = hashNew (0);
    if (topologyEntriesHashTable == NULL) {
        LOGE ("Create topologyEntriesHashTable error.\n");
        goto destroyTopologyEntriesHashTableRWLock;
    }

    return 0;

destroyTopologyEntriesHashTableRWLock:
    pthread_rwlock_destroy (&topologyEntriesHashTableRWLock);
    return -1;
}

/* Destroy topology manager */
void
destroyTopologyManager (void) {
    pthread_rwlock_destroy (&topologyEntriesHashTableRWLock);
    hashDestroy (topologyEntriesHashTable);
    topologyEntriesHashTable = NULL;
}
