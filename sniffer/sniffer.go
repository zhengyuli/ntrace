package sniffer

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	"bitbucket.org/zhengyuli/ntrace/sniffer/driver"
	"bitbucket.org/zhengyuli/ntrace/sniffer/driver/pcap"
)

// Sniffer network sniffer
type Sniffer interface {
	DatalinkType() layers.DatalinkType
	SetFilter(filter string) error
	NextPacket(pkt *driver.Packet) error
	Stats() (*driver.Stats, error)
	Close() error
}

// New create a new sniffer.
func New(netDev string) (Sniffer, error) {
	return pcap.Open(netDev)
}
