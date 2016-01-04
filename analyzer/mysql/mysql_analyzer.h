#ifndef __MYSQL_ANALYZER_H__
#define __MYSQL_ANALYZER_H__

#include "util.h"
#include "proto_analyzer.h"

typedef struct _mysqlHeader mysqlHeader;
typedef mysqlHeader *mysqlHeaderPtr;

/* Normal mysql header */
struct _mysqlHeader {
    u_int payloadLen:24;
    u_int pktId:8;
};

#define MYSQL_HEADER_SIZE 4

typedef struct _mysqlCompHeader mysqlCompHeader;
typedef mysqlCompHeader *mysqlCompHeaderPtr;

/* Compressed mysql header */
struct _mysqlCompHeader {
    u_int compPayloadLen:24;
    u_int compPktId:8;
    u_int payloadLen:24;
};

#define MYSQL_COMPRESSED_HEADER_SIZE 7

/* Mysql field type */
typedef enum {
    FIELD_TYPE_DECIMAL = 0,
    FIELD_TYPE_TINY = 1,
    FIELD_TYPE_SHORT = 2,
    FIELD_TYPE_LONG = 3,
    FIELD_TYPE_FLOAT = 4,
    FIELD_TYPE_DOUBLE = 5,
    FIELD_TYPE_NULL = 6,
    FIELD_TYPE_TIMESTAMP = 7,
    FIELD_TYPE_LONGLONG = 8,
    FIELD_TYPE_INT24 = 9,
    FIELD_TYPE_DATE = 10,
    FIELD_TYPE_TIME = 11,
    FIELD_TYPE_DATETIME = 12,
    FIELD_TYPE_YEAR = 13,
    FIELD_TYPE_NEWDATE = 14,
    FIELD_TYPE_VARCHAR = 15,
    FIELD_TYPE_BIT = 16,
    FIELD_TYPE_NEWDECIMAL = 246,
    FIELD_TYPE_ENUM = 247,
    FIELD_TYPE_SET = 248,
    FIELD_TYPE_TINY_BLOB = 249,
    FIELD_TYPE_MEDIUM_BLOB = 250,
    FIELD_TYPE_LONG_BLOB = 251,
    FIELD_TYPE_BLOB = 252,
    FIELD_TYPE_VAR_STRING = 253,
    FIELD_TYPE_STRING = 254,
    FIELD_TYPE_GEOMETRY = 255
} mysqlFieldType;

/* Mysql field flag */
#define NOT_NULL_FLAG         (1 << 0)
#define PRI_KEY_FLAG          (1 << 1)
#define UNIQUE_KEY_FLAG       (1 << 2)
#define MULTIPLE_KEY_FLAG     (1 << 3)
#define BLOB_FLAG             (1 << 4)
#define UNSIGNED_FLAG         (1 << 5)
#define ZEROFILL_FLAG         (1 << 6)
#define BINARY_FLAG           (1 << 7)
#define ENUM_FLAG             (1 << 8)
#define AUTO_INCREMENT_FLAG   (1 << 9)
#define TIMESTAMP_FLAG        (1 << 10)
#define SET_FLAG              (1 << 11)
#define NO_DEFAULT_VALUE_FLAG (1 << 12)
#define NUM_FLAG              (1 << 13)

/* Mysql command */
typedef enum {
    /* 0 */
    COM_SLEEP, COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST,
    /* 5 */
    COM_CREATE_DB, COM_DROP_DB, COM_REFRESH, COM_SHUTDOWN, COM_STATISTICS,
    /* 10 */
    COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, COM_PING,
    /* 15 */
    COM_TIME, COM_DELAYED_INSERT, COM_CHANGE_USER, COM_BINLOG_DUMP, COM_TABLE_DUMP,
    /* 20 */
    COM_CONNECT_OUT, COM_REGISTER_SLAVE, COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA,
    /* 25 */
    COM_STMT_CLOSE, COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH, COM_DAEMON,
    /* 30 */
    COM_BINLOG_DUMP_GTID, COM_RESET_CONNECTION,
    /* Must be last */
    COM_UNKNOWN
} mysqlCmd;

/* Mysql client capabilitie flags */
#define CLIENT_LONG_PASSWORD                  (1 << 0)
#define CLIENT_FOUND_ROWS                     (1 << 1)
#define CLIENT_LONG_FLAG                      (1 << 2)
#define CLIENT_CONNECT_WITH_DB                (1 << 3)
#define CLIENT_NO_SCHEMA                      (1 << 4)
#define CLIENT_COMPRESS                       (1 << 5)
#define CLIENT_ODBC                           (1 << 6)
#define CLIENT_LOCAL_FILES                    (1 << 7)
#define CLIENT_IGNORE_SPACE                   (1 << 8)
#define CLIENT_PROTOCOL_41                    (1 << 9)
#define CLIENT_INTERACTIVE                    (1 << 10)
#define CLIENT_SSL                            (1 << 11)
#define CLIENT_IGNORE_SIGPIPE                 (1 << 12)
#define CLIENT_TRANSACTIONS                   (1 << 13)
#define CLIENT_RESERVED                       (1 << 14)
#define CLIENT_SECURE_CONNECTION              (1 << 15)
#define CLIENT_MULTI_STATEMENTS               (1 << 16)
#define CLIENT_MULTI_RESULTS                  (1 << 17)
#define CLIENT_PS_MULTI_RESULTS               (1 << 18)
#define CLIENT_PLUGIN_AUTH                    (1 << 19)
#define CLIENT_CONNECT_ATTRS                  (1 << 20)
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA (1 << 21)
#define CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS   (1 << 22)
#define CLIENT_SESSION_TRACK                  (1 << 23)
#define CLIENT_DEPRECATE_EOF                  (1 << 24)

/* Mysql server status */
#define SERVER_STATUS_IN_TRANS             (1 << 0)
#define SERVER_STATUS_AUTOCOMMIT           (1 << 1)
#define SERVER_STATUS_MORE_RESULTS         (1 << 2)
#define SERVER_MORE_RESULTS_EXISTS         (1 << 3)
#define SERVER_QUERY_NO_GOOD_INDEX_USED    (1 << 4)
#define SERVER_QUERY_NO_INDEX_USED         (1 << 5)
#define SERVER_STATUS_CURSOR_EXISTS        (1 << 6)
#define SERVER_STATUS_LAST_ROW_SENT        (1 << 7)
#define SERVER_STATUS_DB_DROPPED           (1 << 8)
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES (1 << 9)

typedef enum {
    STATE_NOT_CONNECTED = 0,
    STATE_CLIENT_HANDSHAKE = 1,
    STATE_SECURE_AUTH = 2,
    STATE_SLEEP = 3,
    STATE_PONG = 4,
    STATE_OK_OR_ERROR = 5,
    STATE_END_OR_ERROR = 6,
    STATE_END = 7,
    STATE_STATISTICS = 8,
    STATE_FIELD_LIST = 9,
    STATE_TXT_RS = 10,
    STATE_TXT_FIELD = 11,
    STATE_TXT_ROW = 12,
    STATE_LOCAL_INFILE_DATA = 13,
    STATE_BIN_RS = 14,
    STATE_BIN_FIELD = 15,
    STATE_BIN_ROW = 16,
    STATE_STMT_META = 17,
    STATE_STMT_PARAM = 18,
    STATE_STMT_FETCH_RS = 19,
    MYSQL_STATE_COUNT = 20
} mysqlState;

/*
 * Mysql events.
 * Events 0-32 are reserved for mysqlCmds
 */
typedef enum {
    EVENT_SERVER_HANDSHAKE = 33,
    EVENT_CLIENT_HANDSHAKE,
    EVENT_SECURE_AUTH,
    EVENT_OK,
    EVENT_ERROR,
    EVENT_END,
    EVENT_END_WITH_MULTI_RESULT,
    EVENT_STATISTICS,
    EVENT_FIELD_LIST_FIELD,
    EVENT_NUM_FIELDS,
    EVENT_TXT_FIELD,
    EVENT_TXT_ROW,
    EVENT_LOCAL_INFILE,
    EVENT_LOCAL_INFILE_DATA,
    EVENT_BIN_FIELD,
    EVENT_BIN_ROW,
    EVENT_STMT_META,
    EVENT_STMT_PARAM,
    EVENT_STMT_FETCH_RESULT,
    EVENT_UNKNOWN
} mysqlEvent;

typedef struct _mysqlCmdCtxt mysqlCmdCtxt;
typedef mysqlCmdCtxt *mysqlCmdCtxtPtr;

struct _mysqlCmdCtxt {
    u_int fieldsCount;                  /**< Fields count */
    u_int fieldsRecv;                   /**< Fields received */
    mysqlFieldType fieldsType [512];    /**< Fields type */
};

typedef struct _mysqlSharedInfo mysqlSharedInfo;
typedef mysqlSharedInfo *mysqlSharedInfoPtr;

struct _mysqlSharedInfo {
    u_int protoVer;                     /**< Mysql protocol version */
    char *serverVer;                    /**< Mysql server version */
    u_int cliCaps;                      /**< Mysql client capability flags */
    boolean cliProtoIsV41;              /**< Mysql client protocol V41 flag */
    u_int conId;                        /**< Mysql connection id */
    u_int maxPktSize;                   /**< Mysql max packet size support */
    boolean doCompress;                 /**< Mysql client compression flag */
    boolean doSSL;                      /**< Mysql client authentication with SSL flag */
    char *userName;                     /**< Mysql user name to access */
};

typedef enum {
    MYSQL_INIT = 0,                     /**< Mysql init state */
    MYSQL_REQUEST_BEGIN,                /**< Mysql request begin */
    MYSQL_REQUEST_COMPLETE,             /**< Mysql request complete */
    MYSQL_RESPONSE_BEGIN,               /**< Mysql response begin */
    MYSQL_RESPONSE_OK,                  /**< Mysql response ok */
    MYSQL_RESPONSE_ERROR,               /**< Mysql response error */
    MYSQL_RESET_TYPE1,                  /**< Mysql reset during request */
    MYSQL_RESET_TYPE2,                  /**< Mysql reset after request and before response */
    MYSQL_RESET_TYPE3,                  /**< Mysql reset during response */
    MYSQL_RESET_TYPE4                   /**< Mysql reset without request */
} mysqlSessionState;

typedef struct _mysqlSessionDetail mysqlSessionDetail;
typedef mysqlSessionDetail *mysqlSessionDetailPtr;

struct _mysqlSessionDetail {
    mysqlCmd cmd;                       /**< Mysql command */
    mysqlCmdCtxt cmdCtxt;               /**< Mysql command context */
    mysqlSharedInfo sharedInfo;         /**< Mysql shared info */
    boolean showC2STag;                 /**< Show client to server tag */
    boolean showS2CTag;                 /**< Show server to client tag */
    mysqlState mstate;                  /**< Mysql state */
    u_int seqId;                        /**< Mysql sequence id */
    char *reqStmt;                      /**< Mysql request statement */
    mysqlSessionState state;            /**< Mysql session state */
    u_short errCode;                    /**< Mysql error code */
    u_int sqlState;                     /**< Mysql sql state */
    char *errMsg;                       /**< Mysql error message */
    u_int reqSize;                      /**< Mysql request size */
    u_int respSize;                     /**< Mysql response size */
    u_long_long reqTime;                /**< Mysql request time */
    u_long_long respTimeBegin;          /**< Mysql response time */
    u_long_long respTimeEnd;            /**< Mysql response time end */
};

typedef enum {
    EVENT_HANDLE_OK = 0,
    EVENT_HANDLE_ERROR = 1
} mysqlEventHandleState;

typedef mysqlEventHandleState (*mysqlEventHandler) (mysqlEvent event,
                                                    u_char *payload,
                                                    u_int payloadLen,
                                                    streamDirection direction);

typedef struct _mysqlEventHandleMap mysqlEventHandleMap;
typedef mysqlEventHandleMap *mysqlEventHandleMapPtr;

struct _mysqlEventHandleMap {
    u_int size;
    mysqlEvent event [32];
    mysqlState nextState [32];
    mysqlEventHandler handler [32];
};

typedef enum {
    MYSQL_BREAKDOWN_OK = 0,             /**< Mysql request ok */
    MYSQL_BREAKDOWN_ERROR,              /**< Mysql request error */
    MYSQL_BREAKDOWN_RESET_TYPE1,        /**< Mysql reset during request */
    MYSQL_BREAKDOWN_RESET_TYPE2,        /**< Mysql reset before response */
    MYSQL_BREAKDOWN_RESET_TYPE3,        /**< Mysql reset during response */
    MYSQL_BREAKDOWN_RESET_TYPE4         /**< Mysql reset without request */
} mysqlBreakdownState;

typedef struct _mysqlSessionBreakdown mysqlSessionBreakdown;
typedef mysqlSessionBreakdown *mysqlSessionBreakdownPtr;

struct _mysqlSessionBreakdown {
    char *serverVer;                    /**< Mysql server version */
    char *userName;                     /**< Mysql user name */
    u_int conId;                        /**< Mysql connection id */
    char *reqStmt;                      /**< Mysql request statement */
    mysqlBreakdownState state;          /**< Mysql breakdown state */
    u_short errCode;                    /**< Mysql error code */
    u_int sqlState;                     /**< Mysql sql state */
    char *errMsg;                       /**< Mysql error message */
    u_int reqSize;                      /**< Mysql request size */
    u_int respSize;                     /**< Mysql response size */
    u_int serverLatency;                /**< Mysql response server latency */
    u_int downloadLatency;              /**< Mysql response download latency */
    u_int respLatency;                  /**< Mysql response latency */
};

/* Mysql session breakdown json key definitions */
#define MYSQL_SBKD_SERVER_VERSION "mysql_server_version"
#define MYSQL_SBKD_USER_NAME "mysql_user_name"
#define MYSQL_SBKD_CONNECTION_ID "mysql_connection_id"
#define MYSQL_SBKD_REQUEST_STATEMENT "mysql_request_statement"
#define MYSQL_SBKD_STATE "mysql_state"
#define MYSQL_SBKD_ERROR_CODE "mysql_error_code"
#define MYSQL_SBKD_SQL_STATE "mysql_sql_state"
#define MYSQL_SBKD_ERROR_MESSAGE "mysql_error_message"
#define MYSQL_SBKD_REQUEST_SIZE "mysql_request_size"
#define MYSQL_SBKD_RESPONSE_SIZE "mysql_response_size"
#define MYSQL_SBKD_SERVER_LATENCY "mysql_server_latency"
#define MYSQL_SBKD_DOWNLOAD_LATENCY "mysql_download_latency"
#define MYSQL_SBKD_RESPONSE_LATENCY "mysql_response_latency"

#endif /* __MYSQL_ANALYZER_H__ */
