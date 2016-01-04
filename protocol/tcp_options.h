#ifndef __TCP_OPTIONS_H__
#define __TCP_OPTIONS_H__

#include <stdlib.h>
#include "util.h"
#include "tcp.h"

/*========================Interfaces definition============================*/
boolean
getTimeStampOption (tcphdrPtr tcph, u_int *ts);
boolean
getTcpWindowScaleOption (tcphdrPtr tcph, u_short *ws);
boolean
getTcpMssOption (tcphdrPtr tcph, u_short *mss);
/*=======================Interfaces definition end=========================*/

#endif /* __TCP_OPTIONS_H__ */
