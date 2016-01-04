#ifndef __RAW_PACKET_H__
#define __RAW_PACKET_H__

#include <stdlib.h>

/*========================Interfaces definition============================*/
u_char *
getIpPacket (u_char *rawPkt, u_int datalinkType);
/*=======================Interfaces definition end=========================*/

#endif /* __RAW_PACKET_H__ */
