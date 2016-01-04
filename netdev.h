#ifndef __NETDEV_H__
#define __NETDEV_H__

#include <pcap.h>
#include "util.h"

/*========================Interfaces definition============================*/
pcap_t *
getNetDevPcapDescForSniff (void);
pcap_t *
getNetDevPcapDescForProtoDetection (void);
int
getNetDevDatalinkTypeForSniff (void);
int
getNetDevDatalinkTypeForProtoDetection (void);
int
getNetDevStatisticInfoForSniff (u_int *pktsRecv, u_int *pktsDrop);
int
getNetDevStatisticInfoForProtoDetection (u_int *pktsRecv, u_int *pktsDrop);
int
updateNetDevFilterForSniff (char *filter);
int
updateNetDevFilterForProtoDetection (char *filter);
int
resetNetDevForSniff (void);
int
initNetDev (void);
void
destroyNetDev (void);
/*=======================Interfaces definition end=========================*/

#endif /* __NETDEV_H__ */
