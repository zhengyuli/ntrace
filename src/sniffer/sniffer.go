package sniffer

import (
	"time"
	"fmt"
	"errors"
	"reflect"
	"sniffer/pcap"
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

type Sniffer struct {
	dev interface{}
}

func (handle *Sniffer) Datalink() (datalink int, err error) {
	switch handle.dev.(type) {
	case *pcap.Pcap:
		return handle.dev.(*pcap.Pcap).Datalink(), nil

	default:
		return -1, errors.New(fmt.Sprintf("Unsupported sniffer type:%v",
			reflect.TypeOf(handle.dev)))
	}
}

func (handle *Sniffer) SetFilter(filter string) error {
	switch handle.dev.(type) {
	case *pcap.Pcap:
		return handle.dev.(*pcap.Pcap).SetFilter(filter)

	default:
		return errors.New(fmt.Sprintf("Unsupported sniffer type:%v",
			reflect.TypeOf(handle.dev)))
	}
}

func (handle *Sniffer) NextPacket() (pkt *Packet, err error) {
	switch handle.dev.(type) {
	case *pcap.Pcap:
		var tmpPkt *pcap.Packet
		tmpPkt, err = handle.dev.(*pcap.Pcap).NextPacket()
		if tmpPkt == nil || err != nil {
			pkt = nil
		} else {
			pkt = new(Packet)
			pkt.Time = tmpPkt.Time
			pkt.CapLen = tmpPkt.CapLen
			pkt.Len = tmpPkt.Len
			pkt.Data = tmpPkt.Data
		}
		return

	default:
		return nil, errors.New(fmt.Sprintf("Unsupported sniffer type:%v",
			reflect.TypeOf(handle.dev)))
	}
}

func (handle *Sniffer) Stats() (stats *Stats, err error) {
	switch handle.dev.(type) {
	case *pcap.Pcap:
		var tmpStats *pcap.Stats
		tmpStats, err = handle.dev.(*pcap.Pcap).Stats()
		if err != nil {
			stats = nil
		} else {
			stats = new(Stats)
			stats.PktsRecvd = tmpStats.PktsRecvd
			stats.PktsDropped = tmpStats.PktsDropped
			stats.PktsIfDropped = tmpStats.PktsIfDropped
		}
		return

	default:
		return nil, errors.New(fmt.Sprintf("Unsupported sniffer type:%v",
			reflect.TypeOf(handle.dev)))
	}
}

func (handle *Sniffer) Close() (error){
	switch handle.dev.(type) {
	case *pcap.Pcap:
		handle.dev.(*pcap.Pcap).Close()
		return nil

	default:
		return errors.New(fmt.Sprintf("Unsupported sniffer type:%v",
			reflect.TypeOf(handle.dev)))
	}
}

func NewSniffer(device string) (handle *Sniffer, err error) {
	handle = new(Sniffer)
	handle.dev, err = pcap.PcapOpenLive(device)
	return
}
