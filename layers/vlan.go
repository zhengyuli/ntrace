package layers

import (
	"encoding/binary"
	"fmt"
)

// VLAN packet layer for 802.1Q VLAN.
type VLAN struct {
	Base
	Priority     uint8
	DropEligible bool
	ID           uint16
	EthernetType EthernetType
}

func (v *VLAN) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("Invalid (too small) VLAN capture length (%d < 4)", len(data))
	}

	v.Priority = (uint8(data[0]) & 0xE0) >> 5
	v.DropEligible = uint8(data[0])&0x10 != 0
	v.ID = binary.BigEndian.Uint16(data[:2]) & 0x0FFF
	v.EthernetType = EthernetType(binary.BigEndian.Uint16(data[2:4]))
	v.Contents = data[:4]
	v.Payload = data[4:]

	return nil
}

func (v *VLAN) NextLayerType() LayerType {
	return v.EthernetType
}

func (v VLAN) String() string {
	desc := "VLAN: "
	desc += fmt.Sprintf("priority=%d, ", v.Priority)
	desc += fmt.Sprintf("dropEligible=%v, ", v.DropEligible)
	desc += fmt.Sprintf("id=%d, ", v.ID)
	desc += fmt.Sprintf("ethernetType=%s", v.EthernetType)

	return desc
}
