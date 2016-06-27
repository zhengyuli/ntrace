package layers

import (
	"fmt"
)

type DatalinkType int

const (
	DatalinkTypeEthernet DatalinkType = 0x0001
)

func (dt DatalinkType) String() string {
	switch dt {
	case DatalinkTypeEthernet:
		return "Ethernet"

	default:
		return fmt.Sprintf("Datalink type 0x%04X", uint16(dt))
	}
}
