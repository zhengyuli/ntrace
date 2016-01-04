#include <stdlib.h>
#include <sched.h>
#include <ini_config.h>
#include "config.h"
#include "log.h"
#include "properties.h"

/* Properties instance */
static propertiesPtr propertiesInstance = NULL;

static propertiesPtr
newProperties (void) {
    propertiesPtr tmp;

    tmp = (propertiesPtr) malloc (sizeof (properties));
    if (tmp == NULL)
        return NULL;

    tmp->daemonMode = False;

    tmp->schedPriority = 0;

    tmp->managementServicePort = 0;

    tmp->interface = NULL;

    tmp->pcapFile = NULL;

    tmp->outputFile = NULL;

    tmp->splunkIndex = NULL;
    tmp->splunkSource = NULL;
    tmp->splunkSourcetype = NULL;
    tmp->splunkAuthToken = NULL;
    tmp->splunkUrl = NULL;

    tmp->autoAddService = True;

    tmp->logDir = NULL;
    tmp->logFileName = NULL;
    tmp->logLevel = LOG_ERR_LEVEL;
    return tmp;
}

static void
freeProperties (propertiesPtr instance) {
    if (instance == NULL)
        return;

    free (instance->interface);
    instance->interface = NULL;

    free (instance->pcapFile);
    instance->pcapFile = NULL;

    free (instance->outputFile);
    instance->outputFile = NULL;

    free (instance->splunkIndex);
    instance->splunkIndex = NULL;
    free (instance->splunkSource);
    instance->splunkSource = NULL;
    free (instance->splunkSourcetype);
    instance->splunkSourcetype = NULL;
    free (instance->splunkAuthToken);
    instance->splunkAuthToken = NULL;
    free (instance->splunkUrl);
    instance->splunkUrl = NULL;

    free (instance->logDir);
    instance->logDir = NULL;
    free (instance->logFileName);
    instance->logFileName = NULL;

    free (instance);
}

static int
validateProperties (propertiesPtr instance) {
    if (instance->interface == NULL && instance->pcapFile == NULL) {
        fprintf (stderr, "There is no input.\n");
        return -1;
    }

    if (instance->interface && instance->pcapFile) {
        fprintf (stderr, "Only one input should be specified.\n");
        return -1;
    }

    if (!((instance->splunkIndex && instance->splunkSource && instance->splunkSourcetype &&
           instance->splunkAuthToken && instance->splunkUrl) ||
          (!instance->splunkIndex && !instance->splunkSource && !instance->splunkSourcetype &&
           !instance->splunkAuthToken && !instance->splunkUrl))) {
        if (instance->splunkIndex == NULL)
            fprintf (stderr, "Missing index for splunkOutput.\n");
        if (instance->splunkSource == NULL)
            fprintf (stderr, "Missing source for splunkOutput.\n");
        if (instance->splunkSourcetype == NULL)
            fprintf (stderr, "Missing sourcetype for splunkOutput.\n");
        if (instance->splunkAuthToken == NULL)
            fprintf (stderr, "Missing authToken for splunkOutput.\n");
        if (instance->splunkUrl == NULL)
            fprintf (stderr, "Missing url for splunkOutput.\n");
        return -1;
    }

    if (!instance->logDir || !instance->logFileName) {
        if (instance->logDir == NULL)
            fprintf (stderr, "Missing logDir for log.\n");
        if (instance->logFileName == NULL)
            fprintf (stderr, "Missing logFileName for log.\n");
        return -1;
    }

    return 0;
}

static propertiesPtr
loadPropertiesFromConfigFile (char *configFile) {
    int ret, error;
    int minPriority;
    int maxPriority;
    struct collection_item *iniConfig = NULL;
    struct collection_item *errorSet = NULL;
    struct collection_item *item;
    propertiesPtr tmp;

    /* Alloc properties */
    tmp = newProperties ();
    if (tmp == NULL) {
        fprintf (stderr, "Alloc properties error.\n");
        return NULL;
    }

    /* Load properties from NTRACE_CONFIG_FILE */
    ret = config_from_file ("main", configFile,
                            &iniConfig, INI_STOP_ON_ANY, &errorSet);
    if (ret) {
        fprintf (stderr, "Parse config file: %s error.\n", configFile);
        goto freeProperties;
    }

    /* Get daemonMode */
    ret = get_config_item ("default", "daemonMode", iniConfig, &item);
    if (ret && item == NULL) {
        fprintf (stderr, "Get_config_item \"daemonMode\" from \"default\" error.\n");
        goto freeProperties;
    }
    ret = get_bool_config_value (item, 0, &error);
    if (error) {
        fprintf (stderr, "Get_config_item \"daemonMode\" from \"default\" error.\n");
        goto freeProperties;
    }
    if (ret)
        tmp->daemonMode = True;
    else
        tmp->daemonMode = False;

    /* Get schedulePolicy priority */
    ret = get_config_item ("schedulePolicy", "priority", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"priority\" from \"schedulePolicy\" error.\n");
        goto freeProperties;
    }
    tmp->schedPriority = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get_config_item \"priority\" from \"schedulePolicy\" error.\n");
        goto freeProperties;
    }

    minPriority = sched_get_priority_min (SCHED_RR);
    maxPriority = sched_get_priority_max (SCHED_RR);

    if (tmp->schedPriority < minPriority ||
        tmp->schedPriority > maxPriority)
        tmp->schedPriority = 0;

    /* Get managementService port */
    ret = get_config_item ("managementService", "port", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"port\" from  \"managementService\" error.\n");
        goto freeProperties;
    }
    tmp->managementServicePort = get_int_config_value (item, 1, 0, &error);
    if (error) {
        fprintf (stderr, "Get_config_item \"port\" from  \"managementService\" error.\n");
        goto freeProperties;
    }

    /* Get liveInput interface */
    ret = get_config_item ("liveInput", "interface", iniConfig, &item);
    if (!ret && item) {
        tmp->interface = strdup (get_const_string_config_value (item, &error));
        if (tmp->interface == NULL) {
            fprintf (stderr, "Get \"interface\" from \"liveInput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get offlineInput pcapFile */
    ret = get_config_item ("offlineInput", "pcapFile", iniConfig, &item);
    if (!ret && item) {
        tmp->pcapFile = strdup (get_const_string_config_value (item, &error));
        if (tmp->pcapFile == NULL) {
            fprintf (stderr, "Get \"pcapFile\" from \"offlineInput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get fileOutput outputFile */
    ret = get_config_item ("fileOutput", "outputFile", iniConfig, &item);
    if (!ret && item) {
        tmp->outputFile = strdup (get_const_string_config_value (item, &error));
        if (tmp->outputFile == NULL) {
            fprintf (stderr, "Get \"outputFile\" from \"fileOutput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get splunkOutput index */
    ret = get_config_item ("splunkOutput", "index", iniConfig, &item);
    if (!ret && item) {
        tmp->splunkIndex = strdup (get_const_string_config_value (item, &error));
        if (tmp->splunkIndex == NULL) {
            fprintf (stderr, "Get \"index\" from \"splunkOutput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get splunkOutput source */
    ret = get_config_item ("splunkOutput", "source", iniConfig, &item);
    if (!ret && item) {
        tmp->splunkSource = strdup (get_const_string_config_value (item, &error));
        if (tmp->splunkSource == NULL) {
            fprintf (stderr, "Get \"source\" from \"splunkOutput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get splunkOutput sourcetype */
    ret = get_config_item ("splunkOutput", "sourcetype", iniConfig, &item);
    if (!ret && item) {
        tmp->splunkSourcetype = strdup (get_const_string_config_value (item, &error));
        if (tmp->splunkSourcetype == NULL) {
            fprintf (stderr, "Get \"sourcetype\" from \"splunkOutput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get splunkOutput authToken */
    ret = get_config_item ("splunkOutput", "authToken", iniConfig, &item);
    if (!ret && item) {
        tmp->splunkAuthToken = strdup (get_const_string_config_value (item, &error));
        if (tmp->splunkAuthToken == NULL) {
            fprintf (stderr, "Get \"authToken\" from \"splunkOutput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get splunkOutput url */
    ret = get_config_item ("splunkOutput", "url", iniConfig, &item);
    if (!ret && item) {
        tmp->splunkUrl = strdup (get_const_string_config_value (item, &error));
        if (tmp->splunkUrl == NULL) {
            fprintf (stderr, "Get \"url\" from \"splunkOutput\" error.\n");
            goto freeProperties;
        }
    }

    /* Get protoDetect autoAddService */
    ret = get_config_item ("protoDetect", "autoAddService", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"autoAddService\" from \"protoDetect\" error.\n");
        goto freeProperties;
    }
    ret = get_bool_config_value (item, 0, &error);
    if (error) {
        fprintf (stderr, "Get_config_item \"autoAddService\" from \"protoDetect\" error.\n");
        goto freeProperties;
    }
    if (ret)
        tmp->autoAddService = True;
    else
        tmp->autoAddService = False;

    /* Get log logDir */
    ret = get_config_item ("log", "logDir", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"logDir\" from \"log\" error.\n");
        goto freeProperties;
    }
    tmp->logDir = strdup (get_const_string_config_value (item, &error));
    if (error) {
        fprintf (stderr, "Get \"logDir\" from \"log\" error.\n");
        goto freeProperties;
    }

    /* Get log logFileName */
    ret = get_config_item ("log", "logFileName", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"logFileName\" from \"log\" error.\n");
        goto freeProperties;
    }
    tmp->logFileName = strdup (get_const_string_config_value (item, &error));
    if (error) {
        fprintf (stderr, "Get \"logFileName\" from \"log\" error.\n");
        goto freeProperties;
    }

    /* Get log logLevel */
    ret = get_config_item ("log", "logLevel", iniConfig, &item);
    if (ret || item == NULL) {
        fprintf (stderr, "Get_config_item \"logLevel\" from \"log\" error.\n");
        goto freeProperties;
    }
    tmp->logLevel = get_int_config_value (item, 1, -1, &error);
    if (error) {
        fprintf (stderr, "Get \"logLevel\" from \"log\" error.\n");
        goto freeProperties;
    }

    ret = validateProperties (tmp);
    if (ret < 0) {
        fprintf (stderr, "Validate properties error.\n");
        goto freeProperties;
    }

    goto exit;

freeProperties:
    freeProperties (tmp);
    tmp = NULL;
exit:
    if (iniConfig)
        free_ini_config (iniConfig);
    if (errorSet)
        free_ini_config_errors (errorSet);
    return tmp;
}

boolean
getPropertiesDaemonMode (void) {
    return propertiesInstance->daemonMode;
}

boolean
getPropertiesSchedRealtime (void) {
    return propertiesInstance->schedPriority ? True : False;
}

u_int
getPropertiesSchedPriority (void) {
    return propertiesInstance->schedPriority;
}

u_short
getPropertiesManagementServicePort (void) {
    return propertiesInstance->managementServicePort;
}

boolean
getPropertiesSniffLive (void) {
    return propertiesInstance->pcapFile == NULL ? True : False;
}

char *
getPropertiesInterface (void) {
    return propertiesInstance->interface;
}

char *
getPropertiesPcapFile (void) {
    return propertiesInstance->pcapFile;
}

char *
getPropertiesOutputFile (void) {
    return propertiesInstance->outputFile;
}

char *
getPropertiesSplunkIndex (void) {
    return propertiesInstance->splunkIndex;
}

char *
getPropertiesSplunkSource (void) {
    return propertiesInstance->splunkSource;
}

char *
getPropertiesSplunkSourcetype (void) {
    return propertiesInstance->splunkSourcetype;
}

char *
getPropertiesSplunkAuthToken (void) {
    return propertiesInstance->splunkAuthToken;
}

char *
getPropertiesSplunkUrl (void) {
    return propertiesInstance->splunkUrl;
}

boolean
getPropertiesAutoAddService (void) {
    if (propertiesInstance->pcapFile)
        return True;
    else
        return propertiesInstance->autoAddService;
}

char *
getPropertiesLogDir (void) {
    return propertiesInstance->logDir;
}

char *
getPropertiesLogFileName (void) {
    return propertiesInstance->logFileName;
}

u_int
getPropertiesLogLevel (void) {
    return propertiesInstance->logLevel;
}

void
displayPropertiesDetail (void) {
    LOGI ("Startup with properties:{\n");
    LOGI ("    daemonMode: %s\n", getPropertiesDaemonMode () ? "True" : "False");
    LOGI ("    scheduleRealtime: %s\n", getPropertiesSchedPriority () ? "True" : "False");
    LOGI ("    schedulePriority: %u\n", getPropertiesSchedPriority ());
    LOGI ("    managementServicePort: %u\n", getPropertiesManagementServicePort ());
    LOGI ("    sniffLiveMode : %s\n", getPropertiesSniffLive () ? "True" : "False");
    LOGI ("    interface: %s\n", getPropertiesInterface ());
    LOGI ("    pcapFile: %s\n", getPropertiesPcapFile ());
    LOGI ("    outputFile: %s\n", getPropertiesOutputFile ());
    LOGI ("    splunkIndex: %s\n", getPropertiesSplunkIndex ());
    LOGI ("    splunkSource: %s\n", getPropertiesSplunkSource ());
    LOGI ("    splunkSourcetype: %s\n", getPropertiesSplunkSourcetype ());
    LOGI ("    splunkAuthToken: %s\n", getPropertiesSplunkAuthToken ());
    LOGI ("    splunkUrl: %s\n", getPropertiesSplunkUrl ());
    LOGI ("    autoAddService: %s\n", getPropertiesAutoAddService () ? "True" : "False");
    LOGI ("    logDir: %s\n", getPropertiesLogDir ());
    LOGI ("    logFileName: %s\n", getPropertiesLogFileName ());
    LOGI ("    logLevel: ");
    switch (getPropertiesLogLevel ()) {
        case LOG_ERR_LEVEL:
            LOGI ("ERROR\n");
            break;

        case LOG_WARN_LEVEL:
            LOGI ("WARNING\n");
            break;

        case LOG_INFO_LEVEL:
            LOGI ("INFO\n");
            break;

        case LOG_DEBUG_LEVEL:
            LOGI ("DEBUG\n");
            break;

        case LOG_TRACE_LEVEL:
            LOGI ("TRACE\n");
            break;

        default:
            LOGI ("Unknown\n");
    }
    LOGI ("}\n");
}

/* Init properties form configFile */
int
initProperties (char *configFile) {
    propertiesInstance = loadPropertiesFromConfigFile (configFile);
    if (propertiesInstance == NULL) {
        fprintf (stderr, "Load properties from config file error.\n");
        return -1;
    }

    return 0;
}

/* Destroy properties */
void
destroyProperties (void) {
    freeProperties (propertiesInstance);
    propertiesInstance = NULL;
}
