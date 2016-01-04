#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "log.h"
#include "analysis_record.h"
#include "topology_entry.h"

/**
 * @brief Create new topology entry from srcIp and destIp.
 *
 * @param srcIp -- source ip
 * @param destIp -- dest ip
 *
 * @return topology entry if success, else NULL
 */
topologyEntryPtr
newTopologyEntry (char *srcIp, char *destIp) {
    topologyEntryPtr entry;

    entry = (topologyEntryPtr) malloc (sizeof (topologyEntry));
    if (entry == NULL)
        return NULL;

    entry->srcIp = strdup (srcIp);
    if (entry->srcIp == NULL) {
        free (entry);
        return NULL;
    }

    entry->destIp = strdup (destIp);
    if (entry->destIp == NULL) {
        free (entry->srcIp);
        entry->srcIp = NULL;
        free (entry);
        return NULL;
    }

    return entry;
}

void
freeTopologyEntry (topologyEntryPtr entry) {
    if (entry == NULL)
        return;

    free (entry->srcIp);
    entry->srcIp = NULL;
    free (entry->destIp);
    entry->destIp = NULL;
    free (entry);
}

void
freeTopologyEntryForHash (void *data) {
    freeTopologyEntry ((topologyEntryPtr) data);
}

/**
 * @brief Convert topology entry to json.
 *
 * @param entry -- topology entry to convert
 *
 * @return json object if success, else NULL
 */
json_t *
topologyEntry2Json (topologyEntryPtr entry) {
    json_t *root;

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Topology entry source ip */
    json_object_set_new (root, TOPOLOGY_ENTRY_SOURCE_IP, json_string (entry->srcIp));
    /* Topology entry dest ip */
    json_object_set_new (root, TOPOLOGY_ENTRY_DEST_IP, json_string (entry->destIp));

    return root;
}

/**
 * @brief Create topology entry analysis record from tm, srcIp and destIp.
 *
 * @param tm -- timestamp
 * @param srcIp -- source ip
 * @param destIp -- dest ip
 *
 * @return topology entry analysis record if success, else NULL
 */
char *
topologyEntryAnalysisRecord (timeValPtr tm, char *srcIp, char *destIp) {
    char *out;
    json_t *root;
    char buf [64];

    root = json_object ();
    if (root == NULL) {
        LOGE ("Create json object error.\n");
        return NULL;
    }

    /* Analysis record timestamp */
    formatLocalTimeStr (tm, buf, sizeof (buf));
    json_object_set_new (root, ANALYSIS_RECORD_TIMESTAMP,
                         json_string (buf));

    /* Analysis record type */
    json_object_set_new (root, ANALYSIS_RECORD_TYPE,
                         json_string (ANALYSIS_RECORD_TYPE_TOPOLOGY_ENTRY));

    /* Topology entry source ip */
    json_object_set_new (root, TOPOLOGY_ENTRY_SOURCE_IP, json_string (srcIp));

    /* Topology entry dest ip */
    json_object_set_new (root, TOPOLOGY_ENTRY_DEST_IP, json_string (destIp));

    out = json_dumps (root, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_object_clear (root);

    return out;
}
