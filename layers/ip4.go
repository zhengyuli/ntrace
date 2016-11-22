package layers

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPv4Protocol IPv4 protocol type.
type IPv4Protocol uint8

const (
	// IPv4ProtocolICMP IPv4 protocol ICMP.
	IPv4ProtocolICMP IPv4Protocol = 0x01
	// IPv4ProtocolTCP IPv4 protocol TCP.
	IPv4ProtocolTCP IPv4Protocol = 0x06
)

// Name get IPv4 protocol name.
func (p IPv4Protocol) Name() string {
	switch p {
	case IPv4ProtocolICMP:
		return "ICMPv4"

	case IPv4ProtocolTCP:
		return "TCP"

	default:
		return fmt.Sprintf("IPv4 proto 0x%02X", uint8(p))
	}
}

// IPv4Option IPv4 option.
type IPv4Option struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

// IPv4 IPv4 frame.
type IPv4 struct {
	Base
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	ID         uint16
	MF, DF     bool
	FragOffset uint16
	TTL        uint8
	Protocol   IPv4Protocol
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []IPv4Option
}

// GetSrcIP get IPv4 source IP.
func (ip *IPv4) GetSrcIP() string {
	return ip.SrcIP.String()
}

// GetDstIP get IPv4 dest IP.
func (ip *IPv4) GetDstIP() string {
	return ip.DstIP.String()
}

// Decode decode IPv4 frame.
func (ip *IPv4) Decode(data []byte) error {
	ip.Version = uint8(data[0]) >> 4
	ip.IHL = uint8(data[0]) & 0x0F
	ip.TOS = uint8(data[1])
	ip.Length = binary.BigEndian.Uint16(data[2:4])
	ip.ID = binary.BigEndian.Uint16(data[4:6])
	flags := binary.BigEndian.Uint16(data[6:8])
	ip.MF = uint8(flags>>13)&0x01 != 0
	ip.DF = uint8(flags>>13)&0x02 != 0
	ip.FragOffset = flags & 0x1FFF
	ip.Protocol = IPv4Protocol(data[9])
	ip.Checksum = binary.BigEndian.Uint16(data[10:12])
	ip.SrcIP = data[12:16]
	ip.DstIP = data[16:20]

	if int(ip.IHL*4) < 20 {
		return fmt.Errorf("invalid (too small) IPv4 header length (%d < 20)", ip.IHL*4)
	}
	if int(ip.Length) < int(ip.IHL*4) {
		return fmt.Errorf("invalid IPv4 length < IPv4 header length (%d < %d)", ip.Length, ip.IHL*4)
	}
	if len(data) < int(ip.Length) {
		return fmt.Errorf("invalid (too small) IPv4 capture length < IPv4 length (%d < %d)", len(data), ip.Length)
	}

	data = data[:ip.Length]
	ip.Contents = data[:ip.IHL*4]
	ip.Payload = data[ip.IHL*4:]

	// IPv4 options
	data = data[20 : ip.IHL*4]
	for len(data) > 0 {
		if ip.Options == nil {
			ip.Options = make([]IPv4Option, 0, 4)
		}
		opt := IPv4Option{OptionType: uint8(data[0])}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			ip.Options = append(ip.Options, opt)
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
				"IPv4 option length exceeds remaining IPv4 header size, option type %d length %d",
				opt.OptionType, opt.OptionLength)
		}
		ip.Options = append(ip.Options, opt)
	}

	return nil
}

// NextLayerType get IPv4 next layer type.
func (ip *IPv4) NextLayerType() LayerType {
	return ip.Protocol
}

// NextLayerDecoder get IPv4 next layer decoder.
func (ip *IPv4) NextLayerDecoder() Decoder {
	switch ip.Protocol {
	case IPv4ProtocolICMP:
		return new(ICMPv4)

	case IPv4ProtocolTCP:
		return new(TCP)

	default:
		return nil
	}
}

func (ip IPv4) String() string {
	desc := "IPv4: "
	desc += fmt.Sprintf("version=%d, ", ip.Version)
	desc += fmt.Sprintf("ipHeaderLength=%d, ", ip.IHL*4)
	desc += fmt.Sprintf("TOS=%d, ", ip.TOS)
	desc += fmt.Sprintf("length=%d, ", ip.Length)
	desc += fmt.Sprintf("id=%d, ", ip.ID)
	desc += fmt.Sprintf("MF=%t, ", ip.MF)
	desc += fmt.Sprintf("DF=%t, ", ip.DF)
	desc += fmt.Sprintf("fragOffset=%d, ", ip.FragOffset)
	desc += fmt.Sprintf("TTL=%d, ", ip.TTL)
	desc += fmt.Sprintf("protocol=%s, ", ip.Protocol.Name())
	desc += fmt.Sprintf("checksum=%d, ", ip.Checksum)
	desc += fmt.Sprintf("srcIP=%s, ", ip.SrcIP)
	desc += fmt.Sprintf("dstIP=%s, ", ip.DstIP)
	desc += fmt.Sprintf("options=%v", ip.Options)

	return desc
}
