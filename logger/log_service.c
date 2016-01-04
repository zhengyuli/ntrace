#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <czmq.h>
#include <locale.h>
#include "util.h"
#include "list.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "log_service.h"

/* Log devices list */
static listHead logDevices;

typedef struct _logDev logDev;
typedef logDev *logDevPtr;
/*
 * Log service output dev, every dev has three interfaces,
 * you can add new log dev to logDevices list with logDevAdd
 * interface.
 */
struct _logDev {
    /* Log dev private data */
    void *data;

    /* Log dev init operation */
    int (*init) (logDevPtr dev);
    /* Log dev destroy operation */
    void (*destroy) (logDevPtr dev);
    /* Log dev write operation */
    void (*write) (char *logMsg, logDevPtr dev);

    /* Log dev list node of global log devices */
    listHead node;
};

/*=================================Log file dev=================================*/

#define LOG_FILE_MAX_SIZE (512 << 20)
#define LOG_FILE_ROTATION_COUNT 16
#define LOG_FILE_SIZE_CHECK_THRESHOLD 500
#define LOG_FILE_PATH_MAX_LEN 512

typedef struct _logFile logFile;
typedef logFile *logFilePtr;

struct _logFile {
    int fd;                             /**< Log file fd */
    char *filePath;                     /**< Log file path */
    u_int checkCount;                   /**< Log file size check count */
};

static boolean
logFileOversize (char *filePath) {
    int ret;
    struct stat fileStat;

    ret = stat (filePath, &fileStat);
    if (ret < 0)
        return True;

    if (fileStat.st_size >= LOG_FILE_MAX_SIZE)
        return True;
    else
        return False;
}

static int
logFileRotate (char *logFileName) {
    int ret;
    int index;
    char fileNameBuf1 [LOG_FILE_PATH_MAX_LEN];
    char fileNameBuf2 [LOG_FILE_PATH_MAX_LEN];

    for (index = (LOG_FILE_ROTATION_COUNT - 1); index > 0; index--) {
        if (index == (LOG_FILE_ROTATION_COUNT - 1)) {
            snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, index);
            if (fileExist (fileNameBuf2)) {
                ret = remove (fileNameBuf2);
                if (ret < 0) {
                    fprintf (stderr, "Log file rotate error.\n");
                    return -1;
                }
            }
        } else {
            snprintf (fileNameBuf1, sizeof (fileNameBuf1), "%s_%d", logFileName, index);
            snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, index + 1);
            if (fileExist (fileNameBuf1)) {
                ret = rename (fileNameBuf1, fileNameBuf2);
                if (ret < 0) {
                    fprintf (stderr, "Log file rotate error.\n");
                    return -1;
                }
            }
        }
    }

    if (LOG_FILE_ROTATION_COUNT == 1) {
        ret = remove (logFileName);
        if (ret < 0) {
            fprintf (stderr, "Log file rotate error.\n");
            return -1;
        }
    } else {
        snprintf (fileNameBuf2, sizeof (fileNameBuf2), "%s_%d", logFileName, 1);
        ret = rename (logFileName, fileNameBuf2);
        if (ret < 0) {
            fprintf (stderr, "Log file rotate error.\n");
            return -1;
        }
    }

    return 0;
}

static int
logFileUpdate (logDevPtr dev) {
    int ret;
    logFilePtr logfile = (logFilePtr) dev->data;

    close (logfile->fd);
    ret = logFileRotate (logfile->filePath);
    if (ret < 0) {
        fprintf (stderr, "Log file rotate error.\n");
        return -1;
    }

    logfile->fd = open (logfile->filePath, O_WRONLY | O_APPEND | O_CREAT, 0755);
    if (logfile->fd < 0) {
        fprintf (stderr, "Open log file error.\n");
        return -1;
    }

    logfile->checkCount = 0;
    return 0;
}

static int
initLogFile (logDevPtr dev) {
    char logFilePath [LOG_FILE_PATH_MAX_LEN];
    logFilePtr logfile;

    if (!fileExist (getPropertiesLogDir ()) &&
        mkdir (getPropertiesLogDir (), 0755) < 0) {
        fprintf (stderr, "Mkdir %s error.\n", getPropertiesLogDir ());
        return -1;
    }

    logfile = (logFilePtr) malloc (sizeof (logFile));
    if (logfile == NULL) {
        fprintf (stderr, "Malloc logFile error.\n");
        return -1;
    }

    snprintf (logFilePath, sizeof (logFilePath), "%s/%s",
              getPropertiesLogDir (), getPropertiesLogFileName ());
    logfile->filePath = strdup (logFilePath);
    if (logfile->filePath == NULL) {
        fprintf (stderr, "Join log file path error.\n");
        free (logfile);
        return -1;
    }
    logfile->fd = open (logfile->filePath, O_WRONLY | O_APPEND | O_CREAT, 0755);
    if (logfile->fd < 0) {
        fprintf (stderr, "Open log file error.\n");
        free (logfile->filePath);
        free (logfile);
        return -1;
    }
    logfile->checkCount = 0;

    dev->data = logfile;
    return 0;
}

static void
destroyLogFile (logDevPtr dev) {
    logFilePtr logfile = (logFilePtr) dev->data;

    close (logfile->fd);
    free (logfile->filePath);
    free (logfile);
}

static int
resetLogFile (logDevPtr dev) {
    destroyLogFile (dev);
    return initLogFile (dev);
}

static void
writeLogFile (char *logMsg, logDevPtr dev) {
    int ret;
    logFilePtr logfile;

    logfile = (logFilePtr) dev->data;
    ret = safeWrite (logfile->fd, logMsg, strlen (logMsg));
    if (ret < 0 || ret != strlen (logMsg)) {
        ret = resetLogFile (dev);
        if (ret < 0)
            fprintf (stderr, "Reset log file error.\n");
        return;
    }

    logfile->checkCount++;
    if (logfile->checkCount >= LOG_FILE_SIZE_CHECK_THRESHOLD &&
        logFileOversize (logfile->filePath)) {
        ret = logFileUpdate (dev);
        if (ret < 0)
            fprintf (stderr, "Log file update error.\n");
    }
    sync ();
}

/*=================================Log file dev=================================*/

/*=================================Log net dev==================================*/

typedef struct _logNet logNet;
typedef logNet *logNetPtr;

struct _logNet {
    void *pubSock;
};

static int
initLogNet (logDevPtr dev) {
    logNetPtr lognet;

    lognet = (logNetPtr) malloc (sizeof (logNet));
    if (lognet == NULL) {
        fprintf (stderr, "Malloc logNet error.\n");
        return -1;
    }

    lognet->pubSock = getLogPubSock ();

    dev->data = lognet;
    return 0;
}

static void
destroyLogNet (logDevPtr dev) {
    return;
}

static void
writeLogNet (char *logMsg, logDevPtr dev) {
    int ret;
    logNetPtr lognet;
    u_int retries = 3;

    lognet = (logNetPtr) dev->data;
    do {
        ret = zstr_send (lognet->pubSock, logMsg);
        retries -= 1;
    } while (ret < 0 && retries);

    if (ret < 0)
        fprintf (stderr, "Publish log message error.\n");
}

/*=================================Log net dev==================================*/

static int
logDevAdd (logDevPtr dev) {
    int ret;

    ret = dev->init (dev);
    if (ret < 0) {
        fprintf (stderr, "Init log dev error.\n");
        return -1;
    }

    listAdd (&dev->node, &logDevices);

    return 0;
}

static void
logDevDestroy (void) {
    logDevPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &logDevices, node) {
        entry->destroy (entry);
        listDel (&entry->node);
    }
}

static void
logDevWrite (listHeadPtr logDevices, char *logMsg) {
    logDevPtr dev;
    listHeadPtr pos;

    listForEachEntry (dev, pos, logDevices, node) {
        dev->write (logMsg, dev);
    }
}

void *
logService (void *args) {
    int ret;
    void *logRecvSock;
    char *logMsg;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log file dev */
    logDev logFileDev = {
        .data = NULL,
        .init = initLogFile,
        .destroy = destroyLogFile,
        .write = writeLogFile,
    };

    /* Init log net dev */
    logDev logNetDev = {
        .data = NULL,
        .init = initLogNet,
        .destroy = destroyLogNet,
        .write = writeLogNet,
    };

    initListHead (&logDevices);

    /* Add file log dev */
    ret = logDevAdd (&logFileDev);
    if (ret < 0)
        goto destroyLogDev;

    /* Add net log dev */
    ret = logDevAdd (&logNetDev);
    if (ret < 0)
        goto destroyLogDev;

    logRecvSock = getLogRecvSock ();
    while (!taskShouldExit ()) {
        logMsg = zstr_recv (logRecvSock);
        if (logMsg == NULL) {
            if (!taskShouldExit ())
                LOGE ("Receive log message with fatal error.\n");
            break;
        }

        logDevWrite (&logDevices, logMsg);
        free (logMsg);
    }

    fprintf (stdout, "LogService will exit... .. .\n");
destroyLogDev:
    logDevDestroy ();
    if (!taskShouldExit ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
