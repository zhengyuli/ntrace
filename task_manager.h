#ifndef __TASK_MANAGER_H__
#define __TASK_MANAGER_H__

#include <pthread.h>
#include <czmq.h>
#include "util.h"

typedef void * (*taskRoutine) (void *args);

typedef enum {
    TASK_STATUS_EXIT_NORMALLY,
    TASK_STATUS_EXIT_ABNORMALLY
} taskStatus;

typedef struct _taskItem taskItem;
typedef taskItem *taskItemPtr;

struct _taskItem {
    char name [64];                     /**< Task name */
    pthread_t tid;                      /**< Task thread id */
    taskRoutine routine;                /**< Task routine */
    void *args;                         /**< Task routine arguments */
    pthread_attr_t attr;                /**< Task thread attribute */
};

/*========================Interfaces definition============================*/
int
newNormalTask (char *taskName, taskRoutine routine, void *args);
int
newRealTask (char *taskName, taskRoutine routine, void *args);
void
stopAllTask (void);
void
sendTaskStatus (taskStatus status);
void
displayTaskSchedPolicyInfo (char *taskName);
int
taskStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg);
int
initTaskManager (void);
void
destroyTaskManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __TASK_MANAGER_H__ */
