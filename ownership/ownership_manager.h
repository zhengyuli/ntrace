#ifndef __OWNERSHIP_MANAGER_H__
#define __OWNERSHIP_MANAGER_H__

#include <stdlib.h>
#include "ownership.h"

/*========================Interfaces definition============================*/
inline void *
getOwnershipPktDispatchSock (u_int hash);
int
initOwnershipManager (void);
void
destroyOwnershipManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __OWNERSHIP_MANAGER_H__ */
