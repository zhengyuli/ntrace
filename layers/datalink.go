package layers

import (
	"fmt"
)

type DatalinkType int

const (
	DatalinkTypeNull     DatalinkType = 0x0000
	DatalinkTypeEthernet DatalinkType = 0x0001
	DatalinkTypeLoop     DatalinkType = 0x006C
)

func (dt DatalinkType) Name() string {
	switch dt {
	case DatalinkTypeNull,
		DatalinkTypeLoop:
		return "Loop"

	case DatalinkTypeEthernet:
		return "Ethernet"

	default:
		return fmt.Sprintf("datalink type 0x%04X", uint16(dt))
	}
}

func (dt DatalinkType) NewDecoder() Decoder {
	switch dt {
	case DatalinkTypeNull,
		DatalinkTypeLoop:
		return new(Loopback)

	case DatalinkTypeEthernet:
		return new(Ethernet)

	default:
		return nil
	}
}
