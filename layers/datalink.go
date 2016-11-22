package layers

import (
	"fmt"
)

// DatalinkType network data link layer type.
type DatalinkType int

const (
	// DatalinkTypeNull data link layer Null
	DatalinkTypeNull DatalinkType = 0x0000
	// DatalinkTypeEthernet data link layer Ethernet
	DatalinkTypeEthernet DatalinkType = 0x0001
	// DatalinkTypeLoop data link layer Loop
	DatalinkTypeLoop DatalinkType = 0x006C
)

// Name get data link layer type name.
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

// NewDecoder get a new data link layer decoder by data link type.
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
