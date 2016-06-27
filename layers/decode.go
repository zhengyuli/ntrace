package layers

import (
	"time"
)

type LayerType interface{}

var NullLayerType LayerType

type Decoder interface {
	Decode(data []byte) error
	LayerContents() []byte
	LayerPayload() []byte
	NextLayerType() LayerType
}

var NullDecoder Decoder

func NewDecoder(layer LayerType) Decoder {
	switch layer {
	case DatalinkTypeEthernet:
		return new(Ethernet)

	case EthernetTypeVLAN:
		return new(VLAN)

	case EthernetTypeIPv4:
		return new(IPv4)

	case IPv4ProtocolICMP:
		return new(ICMPv4)

	case IPv4ProtocolTCP:
		return new(TCP)

	default:
		return NullDecoder
	}
}

type DecodeContext struct {
	Time             time.Time
	DatalinkDecoder  Decoder
	NetworkDecoder   Decoder
	TransportDecoder Decoder
}
