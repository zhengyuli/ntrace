#ifndef __LOG_H__
#define __LOG_H__

#include <stdlib.h>

#define LOG_ERR_LEVEL 0
#define LOG_WARN_LEVEL 1
#define LOG_INFO_LEVEL 2
#define LOG_DEBUG_LEVEL 3
#define LOG_TRACE_LEVEL 4

/*========================Interfaces definition============================*/
void
doLog (u_char logLevel, const char *file, u_int line, const char *func, char *msg, ...);

#define LOGE(...) doLog (LOG_ERR_LEVEL, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#define LOGW(...) doLog (LOG_WARN_LEVEL, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#define LOGI(...) doLog (LOG_INFO_LEVEL, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#define LOGD(...) doLog (LOG_DEBUG_LEVEL, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#define LOGT(...) doLog (LOG_TRACE_LEVEL, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

int
initLogContext (u_int logLevel);
void
destroyLogContext (void);
/*=======================Interfaces definition end=========================*/

#endif /* __LOG_H__ */
