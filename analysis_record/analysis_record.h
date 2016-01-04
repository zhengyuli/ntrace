#ifndef __ANALYSIS_RECORD_H__
#define __ANALYSIS_RECORD_H__

/* Analysis record json key definitions */
#define ANALYSIS_RECORD_TIMESTAMP "timestamp"
#define ANALYSIS_RECORD_TYPE "type"

/* Analysis record type */
#define ANALYSIS_RECORD_TYPE_TOPOLOGY_ENTRY "TOPOLOGY_ENTRY"
#define ANALYSIS_RECORD_TYPE_APP_SERVICE "APP_SERVICE"
#define ANALYSIS_RECORD_TYPE_ICMP_ERROR "ICMP_ERROR"
#define ANALYSIS_RECORD_TYPE_TCP_BREAKDOWN "TCP_BREAKDOWN"

/*========================Interfaces definition============================*/
int
publishAnalysisRecord (void *sendSock, char *analysisRecord);
/*=======================Interfaces definition end=========================*/

#endif /* __ANALYSIS_RECORD_H__ */
