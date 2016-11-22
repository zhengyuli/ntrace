package layers

import (
	"encoding/binary"
	"fmt"
	"net"
)

// EthernetType ethernet type.
type EthernetType uint16

const (
	// EthernetTypeIPv4 ethernet IPv4.
	EthernetTypeIPv4 EthernetType = 0x0800
	// EthernetTypeVLAN ethernet VLAN.
	EthernetTypeVLAN EthernetType = 0x8100
)

// Name get ethernet type name.
func (et EthernetType) Name() string {
	switch et {
	case EthernetTypeIPv4:
		return "IPv4"

	case EthernetTypeVLAN:
		return "VLAN"

	default:
		return fmt.Sprintf("ethernet type 0x%04X", uint16(et))
	}
}

// Ethernet ethernet frame.
type Ethernet struct {
	Base
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   EthernetType
}

// Decode decode ethernet frame.
func (eth *Ethernet) Decode(data []byte) error {
	if len(data) < 14 {
		return fmt.Errorf("invalid (too small) Ethernet capture length (%d < 14)", len(data))
	}

	eth.DstMAC = net.HardwareAddr(data[0:6])
	eth.SrcMAC = net.HardwareAddr(data[6:12])
	eth.EthernetType = EthernetType(binary.BigEndian.Uint16(data[12:14]))
	eth.Contents = data[:14]
	eth.Payload = data[14:]

	return nil
}

// NextLayerType get ethernet next layer type.
func (eth *Ethernet) NextLayerType() LayerType {
	return eth.EthernetType
}

// NextLayerDecoder get ethernet next layer decoder.
func (eth *Ethernet) NextLayerDecoder() Decoder {
	switch eth.EthernetType {
	case EthernetTypeIPv4:
		return new(IPv4)

	case EthernetTypeVLAN:
		return new(VLAN)

	default:
		return nil
	}
}

func (eth Ethernet) String() string {
	desc := "Ethernet: "

	desc += fmt.Sprintf("srcMac=%s, ", eth.SrcMAC)
	desc += fmt.Sprintf("dstMac=%s, ", eth.DstMAC)
	desc += fmt.Sprintf("ethernetType=%s", eth.EthernetType.Name())

	return desc
}
