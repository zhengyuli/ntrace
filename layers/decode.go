package layers

import (
	"time"
)

type Decoder interface {
	Decode(data []byte) error
	LayerContents() []byte
	LayerPayload() []byte
	NextLayerType() LayerType
	NextLayerDecoder() Decoder
}

var NullDecoder Decoder

type IPDecoder interface {
	Decoder
	GetSrcIP() string
	GetDstIP() string
}

type DecodeContext struct {
	Time             time.Time
	DatalinkDecoder  Decoder
	NetworkDecoder   Decoder
	TransportDecoder Decoder
}
