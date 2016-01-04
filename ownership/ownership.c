#include <czmq.h>
#include <jansson.h>
#include "list.h"
#include "log.h"
#include "zmq_hub.h"
#include "ownership.h"

/**
 * @brief Create new ownership based on ownership type and ip.
 *
 * @param type -- ownership type
 * @param ip -- ownership ip
 * @param cpuCores -- ownership cpu cores
 * @param totalMem -- ownership total memory in MB
 * @param freeMem -- ownership free memory in MB
 *
 * @return ownership if success else NULL
 */
ownershipPtr
newOwnership (ownershipType type, char *ip,
              u_int cpuCores, u_int totalMem, u_int freeMem) {
    int ret;
    ownershipPtr owner;

    owner = (ownershipPtr) malloc (sizeof (ownership));
    if (owner == NULL)
        return NULL;

    owner->type = type;

    owner->ip = strdup (ip);
    if (owner->ip == NULL) {
        free (owner);
        return NULL;
    }

    owner->cpuCores = cpuCores;

    owner->totalMem = totalMem;

    owner->freeMem = freeMem;

    owner->zmqCtxt = zctx_new ();
    if (owner->zmqCtxt == NULL) {
        LOGE ("Create zmq context error.\n");
        free (owner->ip);
        free (owner);
        return NULL;
    }
    zctx_set_linger (owner->zmqCtxt, 0);
    zctx_set_iothreads (owner->zmqCtxt, 3);

    owner->pktDispatchSock = zsocket_new (owner->zmqCtxt, ZMQ_PUSH);
    if (owner->pktDispatchSock == NULL) {
        LOGE ("Create pktDispatchSock error.\n");
        zctx_destroy (&owner->zmqCtxt);
        free (owner->ip);
        free (owner);
        return NULL;
    }
    zsocket_set_sndhwm (owner->pktDispatchSock, 500000);
    ret = zsocket_connect (owner->pktDispatchSock, "tcp://%s:%u",
                           owner->ip, TCP_PACKET_DISPATCH_RECV_PORT);
    if (ret < 0) {
        LOGE ("Connect to tcp://%s:%u error.\n", owner->ip, TCP_PACKET_DISPATCH_RECV_PORT);
        zctx_destroy (&owner->zmqCtxt);
        free (owner->ip);
        free (owner);
        return NULL;
    }

    initListHead (&owner->node);

    return owner;
}

ownershipPtr
newLocalOwnership (void) {
    u_int cpuCores, totalMem, freeMem;

    cpuCores = getCpuCoresNum ();
    totalMem = getTotalMemory ();
    freeMem = getFreeMemory ();

    return newOwnership (OWNERSHIP_TYPE_LOCAL, "127.0.0.1", cpuCores, totalMem, freeMem);
}

void
freeOwnership (ownershipPtr self) {
    free (self->ip);
    self->ip = NULL;
    zctx_destroy (&self->zmqCtxt);
    free (self);
}
