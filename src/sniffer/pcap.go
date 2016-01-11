package sniffer

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
    pcapPtr *C.pcap_t
}

func (p *Pcap) Datalink() (datalink int, datalinkName string) {
    datalink = int(C.pcap_datalink(p.pcapPtr))
    name := C.pcap_datalink_val_to_name(C.int(datalink))
    if name != nil {
        datalinkName = C.GoString(name)
    } else {
        datalinkName = ""
    }
    return
}

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

func (p *Pcap) NextEx() (pkt *Packet, err error) {
    var pkthdr *C.struct_pcap_pkthdr
    var pktData *C.u_char

    result := int(C.hack_pcap_next_ex(p.pcapPtr, &pkthdr, &pktData))
    if -1 == result {
        return nil, errors.New("Capture packets with fatal error.")
    }

    if 1 == result {
        pkt = new(Packet)
        pkt.Time = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000)
        pkt.CapLen = uint32(pkthdr.caplen)
        pkt.Len = uint32(pkthdr.len)
        pkt.Data = C.GoBytes(unsafe.Pointer(pktData), C.int(pkthdr.caplen))
    }

	return
}

func (p *Pcap) Stats() (stats *Stats, err error) {
    var cstats C.struct_pcap_stat

    if -1 == C.pcap_stats(p.pcapPtr, &cstats) {
        return nil, p.getError()
    }

    stats = new(Stats)
    stats.PktsRecvd = uint32(cstats.ps_recv)
    stats.PktsIfDropped = uint32(cstats.ps_drop)
    stats.PktsIfDropped = uint32(cstats.ps_ifdrop)
    return
}

func (p *Pcap) Close() {
    C.pcap_close(p.pcapPtr)
}

func (p *Pcap) getError() error {
    return errors.New(C.GoString(C.pcap_geterr(p.pcapPtr)))
}

func PcapOpenLive(device string, capLen int,
    promisc bool, timeout int) (handle Sniffer, err error) {
    var dev *C.char
    dev = C.CString(device)
    defer C.free(unsafe.Pointer(dev))

    var pro int
    if promisc {
        pro = 1
    }

    var errBuf *C.char
    errBuf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
    defer C.free(unsafe.Pointer(errBuf))

    tmp := new(Pcap)
    tmp.pcapPtr = C.pcap_open_live(dev, C.int(capLen),
        C.int(pro), C.int(timeout), errBuf)
    if nil == tmp.pcapPtr {
        dev = nil
        err = errors.New(C.GoString(errBuf))
    } else {
		handle = tmp
        err = nil
    }

    return
}
