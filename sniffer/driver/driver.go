package driver

import (
	"time"
)

// Stats driver stats info.
type Stats struct {
	PktsRecvd     uint
	PktsDropped   uint
	PktsIfDropped uint
}

// Packet captured network packet.
type Packet struct {
	Time   time.Time
	CapLen uint
	PktLen uint
	Data   []byte
}
