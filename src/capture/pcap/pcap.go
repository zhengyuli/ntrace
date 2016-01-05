// Interface to both live and offline pcap parsing.
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

int hack_pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
                      u_char **pkt_data) {
    return pcap_next_ex(p, pkt_header, (const u_char **)pkt_data);
}
*/
import "C"

import (
	"errors"
	"time"
	"unsafe"
)

const (
	ERRBUF_SIZE = 256
)

type Pcap struct {
	cptr *C.pcap_t
}

type Stat struct {
	PacketsReceived uint32
	PacketsDropped uint32
	PacketsIfDropped uint32
}

type PacketTime struct {
	Sec  int32
	Usec int32
}

func (p *PacketTime) Time() time.Time {
	return time.Unix(int64(p.Sec), int64(p.Usec)*1000)
}

type Packet struct {
	Time time.Time
	Caplen uint32
	Len uint32
	Data []byte
}

func (p *Pcap) Next() (pkt *Packet) {
	rv, _ := p.NextEx()
	return rv
}

// Openlive opens a device and returns a *Pcap handler
func Openlive(device string, snaplen int32, promisc bool, timeout_ms int32) (handle *Pcap, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)
	var pro int32
	if promisc {
		pro = 1
	}

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	h.cptr = C.pcap_open_live(dev, C.int(snaplen), C.int(pro), C.int(timeout_ms), buf)
	if nil == h.cptr {
		handle = nil
		err = errors.New(C.GoString(buf))
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}

func Openoffline(file string) (handle *Pcap, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)

	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	h.cptr = C.pcap_open_offline(cf, buf)
	if nil == h.cptr {
		handle = nil
		err = errors.New(C.GoString(buf))
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}

func (p *Pcap) NextEx() (pkt *Packet, result int32) {
	var pkthdr *C.struct_pcap_pkthdr

	var buf_ptr *C.u_char
	var buf unsafe.Pointer
	result = int32(C.hack_pcap_next_ex(p.cptr, &pkthdr, &buf_ptr))

	buf = unsafe.Pointer(buf_ptr)
	if nil == buf {
		return
	}

	pkt = new(Packet)
	pkt.Time = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000)
	pkt.Caplen = uint32(pkthdr.caplen)
	pkt.Len = uint32(pkthdr.len)
	pkt.Data = C.GoBytes(buf, C.int(pkthdr.caplen))
	return
}

func (p *Pcap) Close() {
	C.pcap_close(p.cptr)
}

func (p *Pcap) Geterror() error {
	return errors.New(C.GoString(C.pcap_geterr(p.cptr)))
}

func (p *Pcap) Getstats() (stat *Stat, err error) {
	var cstats _Ctype_struct_pcap_stat
	if -1 == C.pcap_stats(p.cptr, &cstats) {
		return nil, p.Geterror()
	}
	stats := new(Stat)
	stats.PacketsReceived = uint32(cstats.ps_recv)
	stats.PacketsDropped = uint32(cstats.ps_drop)
	stats.PacketsIfDropped = uint32(cstats.ps_ifdrop)

	return stats, nil
}

func (p *Pcap) Setfilter(expr string) (err error) {
	var bpf _Ctype_struct_bpf_program
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if -1 == C.pcap_compile(p.cptr, &bpf, cexpr, 1, 0) {
		return p.Geterror()
	}

	if -1 == C.pcap_setfilter(p.cptr, &bpf) {
		C.pcap_freecode(&bpf)
		return p.Geterror()
	}
	C.pcap_freecode(&bpf)
	return nil
}

func Version() string {
	return C.GoString(C.pcap_lib_version())
}

func (p *Pcap) Datalink() int {
	return int(C.pcap_datalink(p.cptr))
}

func (p *Pcap) Setdatalink(dlt int) error {
	if -1 == C.pcap_set_datalink(p.cptr, C.int(dlt)) {
		return p.Geterror()
	}
	return nil
}

func DatalinkValueToName(dlt int) string {
	if name := C.pcap_datalink_val_to_name(C.int(dlt)); name != nil {
		return C.GoString(name)
	}
	return ""
}

func DatalinkValueToDescription(dlt int) string {
	if desc := C.pcap_datalink_val_to_description(C.int(dlt)); desc != nil {
		return C.GoString(desc)
	}
	return ""
}
