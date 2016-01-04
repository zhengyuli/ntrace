#ifndef __PROPERTIES_H__
#define __PROPERTIES_H__

#include <stdlib.h>
#include "util.h"

typedef struct _properties properties;
typedef properties *propertiesPtr;

struct _properties {
    boolean daemonMode;                 /**< Daemon mode */

    u_int schedPriority;                /**< Schedule priority */

    u_short managementServicePort;      /**< Management service port */

    char *interface;                    /**< Network interface */

    char *pcapFile;                     /**< Pcap offline file */

    char *outputFile;                   /**< Output file for analysis record*/

    char *splunkIndex;                  /**< Splunk index for analysis record*/
    char *splunkSource;                 /**< Splunk source for analysis record */
    char *splunkSourcetype;             /**< Splunk sourcetype for analysis record */
    char *splunkAuthToken;              /**< Splunk auth token for http event collector */
    char *splunkUrl;                    /**< Splunk url for http event collector */

    boolean autoAddService;             /**< Auto add detected service to sniff */

    char *logDir;                       /**< Log dir */
    char *logFileName;                  /**< Log file name */
    u_int logLevel;                     /**< Log level */
};

/*========================Interfaces definition============================*/
boolean
getPropertiesDaemonMode (void);
boolean
getPropertiesSchedRealtime (void);
u_int
getPropertiesSchedPriority (void);
u_short
getPropertiesManagementServicePort (void);
boolean
getPropertiesSniffLive (void);
char *
getPropertiesInterface (void);
char *
getPropertiesPcapFile (void);
char *
getPropertiesOutputFile (void);
char *
getPropertiesSplunkIndex (void);
char *
getPropertiesSplunkSource (void);
char *
getPropertiesSplunkSourcetype (void);
char *
getPropertiesSplunkAuthToken (void);
char *
getPropertiesSplunkUrl (void);
boolean
getPropertiesAutoAddService (void);
char *
getPropertiesLogDir (void);
char *
getPropertiesLogFileName (void);
u_int
getPropertiesLogLevel (void);
void
displayPropertiesDetail (void);
int
initProperties (char *configFile);
void
destroyProperties (void);
/*=======================Interfaces definition end=========================*/

#endif /* __PROPERTIES_H__ */
