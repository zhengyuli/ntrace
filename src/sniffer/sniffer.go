package sniffer

import (
	"time"
)

const (
	CAPTURE_LENGTH = 65535
	CAPTURE_TIMEOUT = 500
	CAPTURE_PROMISC = true
)

type Packet struct {
	Time time.Time
	CapLen uint32
	Len uint32
	Data []byte
}

type Stats struct {
	PktsRecvd uint32
	PktsDropped uint32
	PktsIfDropped uint32
}

type Sniffer interface {
	Datalink() (datalink int, datalinkName string)
	SetFilter(filter string) error
	NextEx() (pkt *Packet, err error)
	Stats() (stats *Stats, err error)
	Close()
}

func NewSniffer(device string) (handle Sniffer, err error) {
	return PcapOpenLive(device, CAPTURE_LENGTH,
		CAPTURE_PROMISC, CAPTURE_TIMEOUT)
}
