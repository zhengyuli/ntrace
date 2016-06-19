package layers

import (
	"encoding/binary"
	"fmt"
)

type ICMPv4 struct {
	Base
	Type     uint8
	Code     uint8
	Checksum uint16
}

func (icmp *ICMPv4) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("Invalid (too small) ICMPv4 capture length (%d < 8)", len(data))
	}

	icmp.Type = uint8(data[0])
	icmp.Code = uint8(data[1])
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.Contents = data[:4]
	icmp.Payload = data[4:]

	return nil
}

func (icmp *ICMPv4) NextLayerType() LayerType {
	return NullLayerType
}

func (icmp ICMPv4) String() string {
	desc := "ICMPv4: "

	desc += fmt.Sprintf("type=%d, ", icmp.Type)
	desc += fmt.Sprintf("code=%d, ", icmp.Code)
	desc += fmt.Sprintf("checksum=%d", icmp.Checksum)

	return desc
}
