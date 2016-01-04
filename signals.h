#ifndef __SIGNALS_H__
#define __SIGNALS_H__

#include "util.h"

/*========================Interfaces definition============================*/
boolean
taskShouldExit (void);
void
setupSignals (void);
void
resetSignalsFlag (void);
/*=======================Interfaces definition end=========================*/

#endif /* __SIGNALS_H__ */
