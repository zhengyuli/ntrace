package layers

import (
	"fmt"
)

type LayerType interface{}

var NullLayerType LayerType

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

// Base is a convenience struct which implements the LayerData and
// LayerPayload functions of the Layer interface.
type Base struct {
	// Contents is the set of bytes that make up this layer.  IE: for an
	// Ethernet packet, this would be the set of bytes making up the
	// Ethernet frame.
	Contents []byte
	// Payload is the set of bytes contained by (but not part of) this
	// Layer.  Again, to take Ethernet as an example, this would be the
	// set of bytes encapsulated by the Ethernet protocol.
	Payload []byte
}

// LayerContents returns the bytes of the packet layer.
func (b *Base) LayerContents() []byte { return b.Contents }

// LayerPayload returns the bytes contained within the packet layer.
func (b *Base) LayerPayload() []byte { return b.Payload }
