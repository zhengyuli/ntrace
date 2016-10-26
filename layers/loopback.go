package layers

import (
	"encoding/binary"
	"fmt"
)

type ProtocolFamily uint8

const (
	ProtocolFamilyIPv4 ProtocolFamily = 0x02
)

func (pf ProtocolFamily) Name() string {
	switch pf {
	case ProtocolFamilyIPv4:
		return "IPv4"

	default:
		return fmt.Sprintf("loopback protocol family 0x%04X", uint16(pf))
	}
}

type Loopback struct {
	Base
	Family ProtocolFamily
}

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

func (l *Loopback) NextLayerType() LayerType {
	return l.Family
}

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
