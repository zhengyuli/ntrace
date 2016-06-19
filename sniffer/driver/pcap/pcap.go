package pcap

/*
#cgo linux LDFLAGS: -lpcap
#cgo freebsd LDFLAGS: -lpcap
#cgo darwin LDFLAGS: -lpcap
#cgo windows CFLAGS: -I C:/WpdPack/Include
#cgo windows,386 LDFLAGS: -L C:/WpdPack/Lib -lwpcap
#cgo windows,amd64 LDFLAGS: -L C:/WpdPack/Lib/x64 -lwpcap
#include <stdlib.h>
#include <pcap.h>

int hack_pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, u_char **pkt_data) {
    return pcap_next_ex(p, pkt_header, (const u_char **)pkt_data);
}
*/
import "C"

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	"bitbucket.org/zhengyuli/ntrace/sniffer/driver"
	"errors"
	"time"
	"unsafe"
)

const (
	errBufSize = 256
	maxCapLen  = 65535
	capTimeout = 1000
)

// Pcap pcap descriptor
type Pcap struct {
	pcapPtr *C.pcap_t
}

func (p *Pcap) getError() error {
	return errors.New(C.GoString(C.pcap_geterr(p.pcapPtr)))
}

// DatalinkType get datalink type
func (p *Pcap) DatalinkType() layers.DatalinkType {
	return layers.DatalinkType(C.pcap_datalink(p.pcapPtr))
}

// SetFilter set BPF filter
func (p *Pcap) SetFilter(filter string) error {
	var cfilter *C.char
	cfilter = C.CString(filter)
	defer C.free(unsafe.Pointer(cfilter))

	var bpf C.struct_bpf_program
	if -1 == C.pcap_compile(p.pcapPtr, &bpf, cfilter, 1, 0) {
		return p.getError()
	}
	defer C.pcap_freecode(&bpf)

	if -1 == C.pcap_setfilter(p.pcapPtr, &bpf) {
		return p.getError()
	}

	return nil
}

// NextPacket get next network packet
func (p *Pcap) NextPacket(pkt *driver.Packet) error {
	var pkthdr *C.struct_pcap_pkthdr
	var pktData *C.u_char

	switch int(C.hack_pcap_next_ex(p.pcapPtr, &pkthdr, &pktData)) {
	case 0:
		pkt.Data = nil
		return nil

	case 1:
		pkt.Time = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000)
		pkt.CapLen = uint(pkthdr.caplen)
		pkt.PktLen = uint(pkthdr.len)
		pkt.Data = C.GoBytes(unsafe.Pointer(pktData), C.int(pkthdr.caplen))
		return nil

	default:
		return p.getError()
	}
}

// Stats get network packets capture statistic info
func (p *Pcap) Stats() (*driver.Stats, error) {
	var cstats C.struct_pcap_stat

	if -1 == C.pcap_stats(p.pcapPtr, &cstats) {
		return nil, p.getError()
	}

	stats := new(driver.Stats)
	stats.PktsRecvd = uint(cstats.ps_recv)
	stats.PktsDropped = uint(cstats.ps_drop)
	stats.PktsIfDropped = uint(cstats.ps_ifdrop)
	return stats, nil
}

// Close close pcap handler
func (p *Pcap) Close() error {
	C.pcap_close(p.pcapPtr)

	return nil
}

// Open create a pcap handle for live capture
func Open(netDev string) (*Pcap, error) {
	var dev *C.char
	dev = C.CString(netDev)
	defer C.free(unsafe.Pointer(dev))

	var errBuf *C.char
	errBuf = (*C.char)(C.calloc(errBufSize, 1))
	defer C.free(unsafe.Pointer(errBuf))

	handle := new(Pcap)
	handle.pcapPtr = C.pcap_open_live(dev, C.int(maxCapLen), C.int(1), C.int(capTimeout), errBuf)
	if nil == handle.pcapPtr {
		return nil, errors.New(C.GoString(errBuf))
	}

	return handle, nil
}
