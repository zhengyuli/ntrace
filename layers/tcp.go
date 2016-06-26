package layers

import (
	"encoding/binary"
	"fmt"
)

type TCPOption struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

type TCP struct {
	Base
	SrcPort, DstPort                           uint16
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	Options                                    []TCPOption
}

func (tcp *TCP) Decode(data []byte) error {
	tcp.SrcPort = binary.BigEndian.Uint16(data[0:2])
	tcp.DstPort = binary.BigEndian.Uint16(data[2:4])
	tcp.Seq = binary.BigEndian.Uint32(data[4:8])
	tcp.Ack = binary.BigEndian.Uint32(data[8:12])
	tcp.DataOffset = uint8(data[12]) >> 4
	tcp.FIN = uint8(data[13])&0x01 != 0
	tcp.SYN = uint8(data[13])&0x02 != 0
	tcp.RST = uint8(data[13])&0x04 != 0
	tcp.PSH = uint8(data[13])&0x08 != 0
	tcp.ACK = uint8(data[13])&0x10 != 0
	tcp.URG = uint8(data[13])&0x20 != 0
	tcp.ECE = uint8(data[13])&0x40 != 0
	tcp.CWR = uint8(data[13])&0x80 != 0
	tcp.NS = uint8(data[12])&0x01 != 0
	tcp.Window = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(data[18:20])

	if int(tcp.DataOffset*4) < 20 {
		return fmt.Errorf("Invalid (too small) TCP header length (%d < 20)", tcp.DataOffset*4)
	}
	if len(data) < int(tcp.DataOffset*4) {
		return fmt.Errorf("Invalid (too small) TCP capture length < TCP header length (%d < %d)", len(data), tcp.DataOffset*4)
	}

	tcp.Contents = data[:tcp.DataOffset*4]
	tcp.Payload = data[tcp.DataOffset*4:]

	// TCP options
	data = data[20 : tcp.DataOffset*4]
	for len(data) > 0 {
		if tcp.Options == nil {
			tcp.Options = make([]TCPOption, 0, 4)
		}
		opt := TCPOption{OptionType: uint8(data[0])}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			tcp.Options = append(tcp.Options, opt)
			break

		case 1: // 1 byte padding
			opt.OptionLength = 1

		default:
			opt.OptionLength = data[1]
			opt.OptionData = data[2:opt.OptionLength]
		}
		if len(data) >= int(opt.OptionLength) {
			data = data[opt.OptionLength:]
		} else {
			return fmt.Errorf(
				"TCP option length exceeds remaining TCP header size, option type %d length %d",
				opt.OptionType, opt.OptionLength)
		}
		tcp.Options = append(tcp.Options, opt)
	}

	return nil
}

func (tcp *TCP) NextLayerType() LayerType {
	return NullLayerType
}

func (tcp TCP) String() string {
	desc := "TCP: "
	desc += fmt.Sprintf("srcPort=%d, ", tcp.SrcPort)
	desc += fmt.Sprintf("dstPort=%d, ", tcp.DstPort)
	desc += fmt.Sprintf("sequence=%d, ", tcp.Seq)
	desc += fmt.Sprintf("ack=%d, ", tcp.Ack)
	desc += fmt.Sprintf("dataOffset=%d, ", tcp.DataOffset*4)
	desc += fmt.Sprintf("FIN=%t, ", tcp.FIN)
	desc += fmt.Sprintf("SYN=%t, ", tcp.SYN)
	desc += fmt.Sprintf("RST=%t, ", tcp.RST)
	desc += fmt.Sprintf("PSH=%t, ", tcp.PSH)
	desc += fmt.Sprintf("ACK=%t, ", tcp.ACK)
	desc += fmt.Sprintf("URG=%t, ", tcp.URG)
	desc += fmt.Sprintf("ECE=%t, ", tcp.ECE)
	desc += fmt.Sprintf("CWR=%t, ", tcp.CWR)
	desc += fmt.Sprintf("NS=%t, ", tcp.NS)
	desc += fmt.Sprintf("window=%d, ", tcp.Window)
	desc += fmt.Sprintf("checksum=%d, ", tcp.Checksum)
	desc += fmt.Sprintf("urgent=%d, ", tcp.Urgent)
	desc += fmt.Sprintf("options=%v", tcp.Options)

	return desc
}
