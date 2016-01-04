#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "util.h"
#include "tcp.h"
#include "tcp_options.h"

/**
 * @brief Get tcp timestamp option.
 *
 * @param tcph -- tcp header
 * @param ts -- pointer to return time stamp
 *
 * @return True if time stamp option on else False
 */
boolean
getTimeStampOption (tcphdrPtr tcph, u_int *ts) {
    u_int len;
    u_int timeStamp;
    u_char *options;
    u_int index = 0;

    len = tcph->doff * 4;
    options = (u_char *) (tcph + 1);

    while (index <= (len - sizeof (tcphdr) - 10)) {
        switch (options [index]) {
            case 0:  /* TCPOPT_EOL */
                return False;

            case 1:  /* TCPOPT_NOP */
                index++;
                continue;

            case 8:  /* TCPOPT_TIMESTAMP */
                memcpy ((char *) &timeStamp, options + index + 2, 4);
                *ts = ntohl (timeStamp);
                return True;

            default:  /* Other options */
                if (options [index + 1] < 2)
                    return False;
                index += options [index + 1];
        }
    }

    return False;
}

/**
 * @brief Get tcp window scale option.
 *
 * @param tcph -- tcp header
 * @param ws -- pointer to return window scale
 *
 * @return True if window scale option on else False
 */
boolean
getTcpWindowScaleOption (tcphdrPtr tcph, u_short *ws) {
    u_int len;
    u_char wscale;
    u_char *options;
    u_int index = 0;

    *ws = 1;
    len = 4 * tcph->doff;
    options = (u_char *) (tcph + 1);

    while (index <= (len - sizeof (tcphdr) - 3)) {
        switch (options [index]) {
            case 0:  /* TCPOPT_EOL */
                return False;

            case 1:  /* TCPOPT_NOP */
                index++;
                continue;

            case 3:  /* TCPOPT_WSCALE */
                memcpy ((char *) &wscale, options + index + 2, 1);
                if (wscale > 14)
                    wscale = 14;
                *ws = (1 << wscale);
                return True;

            default:  /* Other options */
                if (options [index + 1] < 2)
                    return False;
                index += options [index + 1];
        }
    }

    return False;
}

/**
 * @brief Get tcp MSS option.
 *
 * @param tcph -- tcp header
 * @param mss -- pointer to return mss
 *
 * @return True if MSS option on else False
 */
boolean
getTcpMssOption (tcphdrPtr tcph, u_short *mss) {
    u_int len;
    u_short maxiumSegSize;
    u_char *options;
    u_int index = 0;

    len = 4 * tcph->doff;
    options = (u_char *) (tcph + 1);

    while (index <= (len - sizeof (tcphdr) - 4)) {
        switch (options [index]) {
            case 0:  /* TCPOPT_EOL */
                return False;

            case 1:  /* TCPOPT_NOP */
                index++;
                continue;

            case 2:  /* TCPOPT_MSS */
                memcpy ((char *) &maxiumSegSize, options + index + 2, 2);
                *mss = ntohs (maxiumSegSize);
                return True;

            default:  /* Other options */
                if (options [index + 1] < 2)
                    return False;
                index += options [index + 1];
        }
    }

    return False;
}
