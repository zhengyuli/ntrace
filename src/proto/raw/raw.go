package raw

import(
	"errors"
)

const (
	// Datalink type
	LINKTYPE_NULL             = 0
	LINKTYPE_ETHERNET         = 1
	LINKTYPE_TOKEN_RING       = 6
	LINKTYPE_ARCNET           = 7
	LINKTYPE_SLIP             = 8
	LINKTYPE_PPP              = 9
	LINKTYPE_FDDI             = 10
	LINKTYPE_ATM_RFC1483      = 100
	LINKTYPE_RAW              = 101
	LINKTYPE_PPP_HDLC         = 50
	LINKTYPE_PPP_ETHER        = 51
	LINKTYPE_C_HDLC           = 104
	LINKTYPE_IEEE802_11       = 105
	LINKTYPE_FRELAY           = 107
	LINKTYPE_LOOP             = 108
	LINKTYPE_LINUX_SLL        = 113
	LINKTYPE_LTALK            = 104
	LINKTYPE_PFLOG            = 117
	LINKTYPE_PRISM_HEADER     = 119
	LINKTYPE_IP_OVER_FC       = 122
	LINKTYPE_SUNATM           = 123
	LINKTYPE_IEEE802_11_RADIO = 127
	LINKTYPE_ARCNET_LINUX     = 129
	LINKTYPE_LINUX_IRDA       = 144
	LINKTYPE_LINUX_LAPD       = 177

	// Ethernet type
    TYPE_IP   = 0x0800
    TYPE_IP6  = 0x86DD
    TYPE_VLAN = 0x8100
)

func GetIpPktOffset(rawPkt []byte, datalinkType int) (offset uint, err error) {
    switch datalinkType {
		// BSD lookback protocol
	case LINKTYPE_NULL, LINKTYPE_LOOP:
        offset = 4

		// Ethernet (10Mb, 100Mb, 1000Mb or higher) protocol
    case LINKTYPE_ETHERNET:
        // Regular ipv4/ipv6 frame
        if (rawPkt [12] == 0x08 && rawPkt [13] == 0x00 ||
			rawPkt [12] == 0x86 && rawPkt [13] == 0xDD) {
			offset = 14
		} else if (rawPkt [12] == 0x81 && rawPkt [13] == 0x00) {
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
            offset = 18
        } else {
            /* Wrong ethernet packet */
            return 0, errors.New("Unsupported packet")
        }

    default:
		return 0, errors.New("Unsupported packet")
    }

	return offset, nil
}
