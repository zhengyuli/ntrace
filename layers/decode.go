package layers

import (
	"time"
)

// Decoder interface of network layer decoder.
type Decoder interface {
	Decode(data []byte) error
	LayerContents() []byte
	LayerPayload() []byte
	NextLayerType() LayerType
	NextLayerDecoder() Decoder
}

// Packet network packet.
type Packet struct {
	Time             time.Time
	DatalinkDecoder  Decoder
	NetworkDecoder   Decoder
	TransportDecoder Decoder
}
