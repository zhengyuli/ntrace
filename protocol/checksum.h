#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include <stdlib.h>

/*========================Interfaces definition============================*/
u_short
ipFastCheckSum (u_char *iph, u_int iphLen);
u_short
tcpFastCheckSum (u_char *tcph, int tcpLen, u_int saddr, u_int daddr);
/*=======================Interfaces definition end=========================*/

#endif /* __CHECKSUM_H__ */
