#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "ip.h"
#include "ip_options.h"

#define ipCheckAddr(x) 0

/**
 * @brief Check ip header options.
 *
 * @param iph -- ip header
 *
 * @return 0 if success, else -1
 */
int
ipOptionsCompile (u_char *iph) {
    ipOptionsPtr opt;
    u_int optLen;
    u_char *optPtr;
    u_char optHolder [16];
    int leftLen;
    u_char *ppPtr = 0;
    u_int skb = 1;
    u_int skbPaAddr = 314159;
    u_int addr;
    u_int midTime;
    u_int *timePtr;
    timestampPtr ts;

    opt = (ipOptionsPtr) optHolder;
    memset (opt, 0, sizeof (ipOptions));
    opt->optLen = ((iphdrPtr) iph)->iphLen * 4 - sizeof (iphdr);
    opt->isData = 0;

    optPtr = iph + sizeof (iphdr);
    for (leftLen = opt->optLen; leftLen > 0;) {
        switch (*optPtr) {
            case IPOPT_END:
                for (optPtr++, leftLen--; leftLen > 0; leftLen--) {
                    if (*optPtr != IPOPT_END) {
                        *optPtr = IPOPT_END;
                        opt->isChanged = 1;
                    }
                }
                goto endOfLine;

            case IPOPT_NOOP:
                leftLen--;
                optPtr++;
                continue;
        }

        optLen = optPtr [1];
        if (optLen < 2 || optLen > leftLen) {
            ppPtr = optPtr;
            goto error;
        }

        switch (*optPtr) {
            case IPOPT_SSRR:
            case IPOPT_LSRR:
                if (optLen < 3) {
                    ppPtr = optPtr + 1;
                    goto error;
                }

                if (optPtr [2] < 4) {
                    ppPtr = optPtr + 2;
                    goto error;
                }

                /* NB: cf RFC-1812 5.2.4.1 */
                if (opt->srr) {
                    ppPtr = optPtr;
                    goto error;
                }

                if (!skb) {
                    if (optPtr [2] != 4 || optLen < 7 || (optLen - 3) & 3) {
                        ppPtr = optPtr + 1;
                        goto error;
                    }

                    memcpy (&opt->faddr, &optPtr [3], 4);

                    if (optLen > 7)
                        memmove (&optPtr [3], &optPtr [7], optLen - 7);
                }

                opt->isStrictRoute = (optPtr [0] == IPOPT_SSRR);
                opt->srr = optPtr - iph;
                break;

            case IPOPT_RR:
                if (opt->rr) {
                    ppPtr = optPtr;
                    goto error;
                }

                if (optLen < 3) {
                    ppPtr = optPtr + 1;
                    goto error;
                }

                if (optPtr [2] < 4) {
                    ppPtr = optPtr + 2;
                    goto error;
                }

                if (optPtr [2] <= optLen) {
                    if (optPtr [2] + 3 > optLen) {
                        ppPtr = optPtr + 2;
                        goto error;
                    }

                    if (skb) {
                        memcpy (&optPtr [optPtr [2] - 1], &skbPaAddr, 4);
                        opt->isChanged = 1;
                    }

                    optPtr [2] += 4;
                    opt->rrNeedAddr = 1;
                }

                opt->rr = optPtr - iph;
                break;

            case IPOPT_TS:
                if (opt->ts) {
                    ppPtr = optPtr;
                    goto error;
                }

                if (optLen < 4) {
                    ppPtr = optPtr + 1;
                    goto error;
                }

                if (optPtr [2] < 5) {
                    ppPtr = optPtr + 2;
                    goto error;
                }

                if (optPtr [2] <= optLen) {
                    ts = (timestampPtr) (optPtr + 1);
                    timePtr = NULL;

                    if ((ts->ptr + 3) > ts->len) {
                        ppPtr = optPtr + 2;
                        goto error;
                    }

                    switch (ts->flags) {
                        case IPOPT_TS_TSONLY:
                            opt->ts = optPtr - iph;

                            if (skb)
                                timePtr = (u_int *) &optPtr [ts->ptr - 1];

                            opt->tsNeedTime = 1;
                            ts->ptr += 4;
                            break;

                        case IPOPT_TS_TSANDADDR:
                            if ((ts->ptr + 7) > ts->len) {
                                ppPtr = optPtr + 2;
                                goto error;
                            }

                            opt->ts = optPtr - iph;

                            if (skb) {
                                memcpy (&optPtr [ts->ptr - 1], &skbPaAddr, 4);
                                timePtr = (u_int *) & optPtr [ts->ptr + 3];
                            }

                            opt->tsNeedAddr = 1;
                            opt->tsNeedTime = 1;
                            ts->ptr += 8;
                            break;

                        case IPOPT_TS_PRESPEC:
                            if ((ts->ptr + 7) > ts->len) {
                                ppPtr = optPtr + 2;
                                goto error;
                            }

                            opt->ts = optPtr - iph;
                            memcpy (&addr, &optPtr [ts->ptr - 1], 4);

                            if (ipCheckAddr (addr) == 0)
                                break;

                            if (skb)
                                timePtr = (u_int *) & optPtr [ts->ptr + 3];

                            opt->tsNeedAddr = 1;
                            opt->tsNeedTime = 1;
                            ts->ptr += 8;
                            break;

                        default:
                            ppPtr = optPtr + 3;
                            goto error;
                    }

                    if (timePtr) {
                        midTime = 1;
                        memcpy (timePtr, &midTime, 4);
                        opt->isChanged = 1;
                    }
                } else {
                    ts = (timestampPtr) (optPtr + 1);

                    if (ts->overflow == 15) {
                        ppPtr = optPtr + 3;
                        goto error;
                    }

                    opt->ts = optPtr - iph;

                    if (skb) {
                        ts->overflow++;
                        opt->isChanged = 1;
                    }
                }
                break;

            case IPOPT_SEC:
            case IPOPT_SID:
            default:
                if (!skb) {
                    ppPtr = optPtr;
                    goto error;
                }
                break;
        }

        leftLen -= optLen;
        optPtr += optLen;
    }

endOfLine:
    opt = (ipOptionsPtr) optHolder;
    if (!ppPtr && !opt->srr)
        return 0;

error:
    return -1;
}
