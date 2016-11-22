package layers

import (
	"encoding/binary"
	"fmt"
)

// VLAN 802.1Q VLAN frame.
type VLAN struct {
	Base
	Priority     uint8
	DropEligible bool
	ID           uint16
	EthernetType EthernetType
}

// Decode decode VLAN frame.
func (v *VLAN) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("invalid (too small) VLAN capture length (%d < 4)", len(data))
	}

	v.Priority = (uint8(data[0]) & 0xE0) >> 5
	v.DropEligible = uint8(data[0])&0x10 != 0
	v.ID = binary.BigEndian.Uint16(data[:2]) & 0x0FFF
	v.EthernetType = EthernetType(binary.BigEndian.Uint16(data[2:4]))
	v.Contents = data[:4]
	v.Payload = data[4:]

	return nil
}

// NextLayerType get VLAN next layer type.
func (v *VLAN) NextLayerType() LayerType {
	return v.EthernetType
}

// NextLayerDecoder get VLAN next layer Decoder.
func (v *VLAN) NextLayerDecoder() Decoder {
	switch v.EthernetType {
	case EthernetTypeIPv4:
		return new(IPv4)

	default:
		return nil
	}
}

func (v VLAN) String() string {
	desc := "VLAN: "
	desc += fmt.Sprintf("priority=%d, ", v.Priority)
	desc += fmt.Sprintf("dropEligible=%v, ", v.DropEligible)
	desc += fmt.Sprintf("id=%d, ", v.ID)
	desc += fmt.Sprintf("ethernetType=%s", v.EthernetType.Name())

	return desc
}
