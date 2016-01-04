#include <stdlib.h>
#include <pcap.h>
#include "log.h"

/**
 * @brief Extract ip packet from raw packet
 *
 * @param rawPkt -- raw packet captured by pcap
 * @param dataLinkType -- datalink type
 *
 * @return Ip packet address if success else NULL
 */
u_char *
getIpPacket (u_char *rawPkt, u_int datalinkType) {
    u_int offset;

    switch (datalinkType) {
        case DLT_NULL:  /* BSD loopback protocol */
            offset = 4;
            break;

        case DLT_EN10MB:  /* Ethernet (10Mb, 100Mb, 1000Mb or higher) protocol */
            /* Regular ip frame */
            if (rawPkt [12] == 0x08 && rawPkt [13] == 0x00)
                offset = 14;
            else if (rawPkt [12] == 0x81 && rawPkt [13] == 0x00) {
                /*
                 * 802.1Q VLAN frame
                 * +----------------------------------------------------------------------+
                 * | Dest Mac: 6 bytes | Src Mac: 6 bytes ||TPID|PCP|CFI|VID|| Ether type |
                 * +----------------------------------------------------------------------+
                 *                                        ^                  ^
                 *                                        |  802.1Q header   |
                 * skip VLAN header, include TPID(Tag Protocal Identifier: 16 bits),
                 * PCP(Priority Code Point: 3 bits), CFI(Canonical Format Indicator: 1 bits) ,
                 * VID(VLAN Identifier: 12 bits)
                 */
                offset = 18;
            } else {
                /* Wrong ip packet */
                LOGE ("Wrong ip packet.\n");
                return NULL;
            }
            break;

        case DLT_IEEE802:  /* IEEE802 protocol */
            offset = 22;
            break;

        case DLT_SLIP:  /* Serial line protocol */
            offset = 0;
            break;

        case DLT_PPP:  /* Point-to-point protocol */
            offset = 4;
            break;

        case DLT_FDDI:  /* FDDI protocol */
            offset = 21;
            break;

        case DLT_RAW:  /* Raw ip protocol */
            offset = 0;
            break;

        case DLT_LINUX_SLL:  /* Linux cooked sockets protocol */
            offset = 16;
            break;

        case DLT_PPP_SERIAL:  /* PPP over serial protocol */
            offset = 4;
            break;

        default:
            LOGE ("Unknown datalink type.\n");
            return NULL;
    }

    return (rawPkt + offset);
}
