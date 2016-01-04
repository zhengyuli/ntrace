#include <string.h>
#include <czmq.h>
#include "analysis_record.h"

/**
 * @brief Publish analysis record to analysis record service.
 *
 * @param sendSock -- sock to send analysis record
 * @param analysisRecord -- analysis record
 *
 * @return 0 if success, else -1
 */
int
publishAnalysisRecord (void *sendSock, char *analysisRecord) {
    zframe_t *frame;

    frame = zframe_new (analysisRecord, strlen (analysisRecord));
    if (frame == NULL)
        return -1;

    return zframe_send (&frame, sendSock, 0);
}
