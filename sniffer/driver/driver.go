package driver

import (
	"time"
)

// Stats driver stats.
type Stats struct {
	PktsRecvd     uint
	PktsDropped   uint
	PktsIfDropped uint
}

// Packet network packet info
type Packet struct {
	Time   time.Time
	CapLen uint
	PktLen uint
	Data   []byte
}
