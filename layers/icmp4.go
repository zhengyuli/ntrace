package layers

import (
	"encoding/binary"
	"fmt"
)

// ICMPv4 ICMPv4 frame.
type ICMPv4 struct {
	Base
	Type     uint8
	Code     uint8
	Checksum uint16
}

// Decode decode ICMPv4 frame.
func (icmp *ICMPv4) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("invalid (too small) ICMPv4 capture length (%d < 8)", len(data))
	}

	icmp.Type = uint8(data[0])
	icmp.Code = uint8(data[1])
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.Contents = data[:4]
	icmp.Payload = data[4:]

	return nil
}

// NextLayerType get ICMPv4 next layer type, always return nil.
func (icmp *ICMPv4) NextLayerType() LayerType {
	return nil
}

// NextLayerDecoder get ICMPv4 next layer decoder, always return nil.
func (icmp *ICMPv4) NextLayerDecoder() Decoder {
	return nil
}

func (icmp ICMPv4) String() string {
	desc := "ICMPv4: "

	desc += fmt.Sprintf("type=%d, ", icmp.Type)
	desc += fmt.Sprintf("code=%d, ", icmp.Code)
	desc += fmt.Sprintf("checksum=%d", icmp.Checksum)

	return desc
}
