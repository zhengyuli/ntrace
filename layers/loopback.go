package layers

import (
	"encoding/binary"
	"fmt"
)

// ProtocolFamily null/loopback protocol type.
type ProtocolFamily uint8

const (
	// ProtocolFamilyIPv4 null/loopback protocol family IPv4
	ProtocolFamilyIPv4 ProtocolFamily = 0x02
)

// Name get null/loopback protocol family name.
func (pf ProtocolFamily) Name() string {
	switch pf {
	case ProtocolFamilyIPv4:
		return "IPv4"

	default:
		return fmt.Sprintf("loopback protocol family 0x%04X", uint16(pf))
	}
}

// Loopback null/loopback protocol frame.
type Loopback struct {
	Base
	Family ProtocolFamily
}

// Decode decode null/loopback protocol frame.
func (l *Loopback) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("invalid (too small) Loopback capture length (%d < 8)", len(data))
	}

	var prot uint32
	if data[0] == 0 && data[1] == 0 {
		prot = binary.BigEndian.Uint32(data[:4])
	} else {
		prot = binary.LittleEndian.Uint32(data[:4])
	}

	l.Family = ProtocolFamily(prot)
	l.Base = Base{Contents: data[:4], Payload: data[4:]}

	return nil
}

// NextLayerType get null/loopback protocol next layer type.
func (l *Loopback) NextLayerType() LayerType {
	return l.Family
}

// NextLayerDecoder get null/loopback protocol next layer decoder.
func (l *Loopback) NextLayerDecoder() Decoder {
	switch l.Family {
	case ProtocolFamilyIPv4:
		return new(IPv4)

	default:
		return nil
	}
}

func (l Loopback) String() string {
	desc := "Loopback: "

	desc += fmt.Sprintf("protocolFamily=%d", l.Family)

	return desc
}
