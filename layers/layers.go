package layers

type LayerType interface {
	Name() string
}

// Base is a convenience struct which implements the LayerContents and
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
