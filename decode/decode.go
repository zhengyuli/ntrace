package decode

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	"time"
)

type Decoder interface {
	Decode(data []byte) error
	LayerContents() []byte
	LayerPayload() []byte
	NextLayerType() layers.LayerType
}

var NullDecoder Decoder

type Context struct {
	Time             time.Time
	DatalinkDecoder  Decoder
	NetworkDecoder   Decoder
	TransportDecoder Decoder
}

func New(layer layers.LayerType) Decoder {
	switch layer {
	case layers.DatalinkTypeEthernet:
		return new(layers.Ethernet)

	case layers.EthernetTypeVLAN:
		return new(layers.VLAN)

	case layers.EthernetTypeIPv4:
		return new(layers.IPv4)

	case layers.IPv4ProtocolICMP:
		return new(layers.ICMPv4)

	case layers.IPv4ProtocolTCP:
		return new(layers.TCP)

	default:
		return NullDecoder
	}
}
