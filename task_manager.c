#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include "util.h"
#include "hash.h"
#include "signals.h"
#include "log.h"
#include "properties.h"
#include "zmq_hub.h"
#include "task_manager.h"

#define TASK_STATUS_MESSAGE_FORMAT_STRING "%u:%lu"
#define TASK_RESTART_MAX_RETRIES 3

/* Task manager hash table */
static hashTablePtr taskManagerHashTable = NULL;

/* Mutext lock for task status send sock */
static pthread_mutex_t taskStatusSendSockLock = PTHREAD_MUTEX_INITIALIZER;

static taskItemPtr
newTaskItem (void) {
    taskItemPtr item;

    item = (taskItemPtr) malloc (sizeof (taskItem));
    if (item == NULL)
        return NULL;

    item->tid = 0;
    item->routine = NULL;
    item->args = NULL;

    return item;
}

static void
freeTaskItem (taskItemPtr item) {
    pthread_attr_destroy (&item->attr);
    free (item);
}

static void
freeTaskItemForHash (void *data) {
    freeTaskItem ((taskItemPtr) data);
}

static int
newTask (char *taskName, taskRoutine routine, void *args, int schedPolicy) {
    int ret;
    struct sched_param param;
    taskItemPtr tsk;
    char key [64];

    tsk = newTaskItem ();
    if (tsk == NULL) {
        LOGE ("Create task item error.\n");
        return -1;
    }

    ret = pthread_attr_init (&tsk->attr);
    if (ret < 0) {
        LOGE ("Init thread attribute error.\n");
        freeTaskItem (tsk);
        return -1;
    }

    if (schedPolicy == SCHED_RR) {
        ret = pthread_attr_setschedpolicy (&tsk->attr, schedPolicy);
        if (ret < 0) {
            LOGE ("Set thread schedule policy error.\n");
            pthread_attr_destroy (&tsk->attr);
            freeTaskItem (tsk);
            return -1;
        }

        ret = pthread_attr_setinheritsched (&tsk->attr, PTHREAD_EXPLICIT_SCHED);
        if (ret < 0) {
            LOGE ("Set thread inherit schedule error.\n");
            pthread_attr_destroy (&tsk->attr);
            freeTaskItem (tsk);
            return -1;
        }

        param.sched_priority = getPropertiesSchedPriority ();
        ret = pthread_attr_setschedparam (&tsk->attr, &param);
        if (ret < 0) {
            LOGE ("Set thread schedule param error.\n");
            pthread_attr_destroy (&tsk->attr);
            freeTaskItem (tsk);
            return -1;
        }
    }

    ret = pthread_create (&tsk->tid, &tsk->attr, routine, args);
    if (ret) {
        if (ret == EAGAIN)
            LOGE ("Insufficient resources to create thread for task: %s.\n", taskName);
        else if (ret == EINVAL)
            LOGE ("Invalid attribute settings to create thread for task: %s.\n", taskName);
        else if (ret == EPERM)
            LOGE ("No permission to create thread for task: %s.\n", taskName);
        else
            LOGE ("Error to create thread for task: %s.\n", taskName);

        pthread_attr_destroy (&tsk->attr);
        freeTaskItem (tsk);
        return -1;
    }

    snprintf (tsk->name, sizeof (tsk->name), "%s", taskName);
    tsk->routine = routine;
    tsk->args = args;
    snprintf (key, sizeof (key), "%lu", tsk->tid);
    ret = hashInsert (taskManagerHashTable, key, tsk, freeTaskItemForHash);
    if (ret < 0) {
        LOGE ("Insert task item error.\n");
        pthread_kill (tsk->tid, SIGUSR1);
        return -1;
    }

    return 0;
}

int
newNormalTask (char *taskName, taskRoutine routine, void *args) {
    return newTask (taskName, routine, args, SCHED_OTHER);
}

int
newRealTask (char *taskName, taskRoutine routine, void *args) {
    if (getPropertiesSchedRealtime ())
        return newTask (taskName, routine, args, SCHED_RR);
    else
        return newTask (taskName, routine, args, SCHED_OTHER);
}

static boolean
stopTaskForEachHashItem (void *data, void *args) {
    int ret;
    taskItemPtr tsk;

    tsk = (taskItemPtr) data;
    ret = pthread_kill (tsk->tid, SIGUSR1);
    if (!ret)
        pthread_join (tsk->tid, NULL);
    else if (ret == ESRCH)
        LOGE ("No thread with the tid: %lu could be found.\n", tsk->tid);
    else
        LOGE ("Stop thread with the tid: %lu failed.\n", tsk->tid);

    return True;
}

void
stopAllTask (void) {
    hashLoopCheckToRemove (taskManagerHashTable, stopTaskForEachHashItem, NULL);
}

static int
restartTask (pthread_t oldTid) {
    int ret;
    taskItemPtr task;
    pthread_t newTid;
    char oldKey [64], newKey [64];

    snprintf (oldKey, sizeof (oldKey), "%lu", oldTid);
    task = hashLookup (taskManagerHashTable, oldKey);
    if (task == NULL) {
        LOGE ("Task with tid: %lu doesn't exist.\n", oldTid);
        return -1;
    }

    ret = pthread_create (&newTid, NULL, task->routine, task->args);
    if (ret < 0) {
        LOGE ("Pthread create task %s error.\n", task->name);
        return -1;
    }

    snprintf (newKey, sizeof (newKey), "%lu", newTid);
    task->tid = newTid;
    ret = hashRename (taskManagerHashTable, oldKey, newKey);
    if (ret < 0) {
        LOGE ("Update task %s tid error.\n", task->name);
        pthread_kill (newTid, SIGUSR1);
        return -1;
    }

    return 0;
}

void
sendTaskStatus (taskStatus status) {
    int ret;
    u_int retries = 3;
    char statusMsg [128];

    snprintf (statusMsg, sizeof (statusMsg),
              TASK_STATUS_MESSAGE_FORMAT_STRING, status, pthread_self ());

    do {
        pthread_mutex_lock (&taskStatusSendSockLock);
        ret = zstr_send (getTaskStatusSendSock (), statusMsg);
        pthread_mutex_unlock (&taskStatusSendSockLock);
        retries -= 1;
    } while (ret < 0 && retries);

    if (ret < 0)
        LOGE ("Send task status error.\n");
}

void
displayTaskSchedPolicyInfo (char *taskName) {
    int ret;
    int policy;
    char *policyName;
    struct sched_param param;

    ret = pthread_getschedparam (pthread_self(), &policy, &param);
    if (ret < 0) {
        LOGE ("Pthread getschedparam error.\n");
        return;
    }

    switch (policy) {
        case SCHED_OTHER:
            policyName = "SCHED_OTHER";
            break;

        case SCHED_RR:
            policyName = "SCHED_RR";
            break;

        case SCHED_FIFO:
            policyName = "SCHED_FIFO";
            break;

        default:
            LOGE ("Unknown schedule policy.\n");
            return;
    }

    LOGI ("Task: %s schedule with policy: %s, static priority: %d\n",
          taskName, policyName, param.sched_priority);
}

int
taskStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    u_int retries;
    taskItemPtr task;
    char *taskStatusMsg;
    char hashKey [64];
    u_int taskStatus;
    pthread_t tid;

    taskStatusMsg = zstr_recv_nowait (getTaskStatusRecvSock ());
    if (taskStatusMsg == NULL) {
        if (!taskShouldExit ()) {
            LOGE ("Receive task status with fatal error.\n");
            return -1;
        }

        return 0;
    }

    sscanf (taskStatusMsg, TASK_STATUS_MESSAGE_FORMAT_STRING, &taskStatus, &tid);
    snprintf (hashKey, sizeof (hashKey), "%lu", tid);
    task = hashLookup (taskManagerHashTable, hashKey);
    if (task == NULL) {
        LOGE ("Get task: %lu error.\n", tid);
        return -1;
    }

    switch (taskStatus) {
        case TASK_STATUS_EXIT_NORMALLY:
            hashRemove (taskManagerHashTable, hashKey);
            break;

        case TASK_STATUS_EXIT_ABNORMALLY:
            LOGE ("%s:%lu exit abnormally.\n",  task->name, tid);
            retries = 1;
            while (retries <= TASK_RESTART_MAX_RETRIES) {
                LOGI ("Try to restart %s with retries: %u\n", task->name, retries);
                ret = restartTask (tid);
                if (!ret)
                    break;

                retries++;
            }

            if (ret < 0) {
                LOGE ("Restart task %s failed.\n", task->name);
                ret = -1;
            } else {
                LOGI ("Restart task %s successfully.\n", task->name);
                ret = 0;
            }
            break;

        default:
            LOGE ("Unknown task status for %s.\n", task->name);
            ret = 0;
            break;
    }

    free (taskStatusMsg);
    return ret;
}

int
initTaskManager (void) {
    taskManagerHashTable = hashNew (0);
    if (taskManagerHashTable == NULL) {
        LOGE ("Create taskManagerHashTable error.\n");
        return -1;
    }

    return 0;
}

void
destroyTaskManager (void) {
    hashDestroy (taskManagerHashTable);
    taskManagerHashTable = NULL;
}
