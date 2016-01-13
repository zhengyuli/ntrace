package tcp

import (
	"errors"
	"encoding/binary"
)

const (
	TCP_NS = 1 << 8
	TCP_CWR = 1 << 7
	TCP_ECE = 1 << 6
	TCP_URG = 1 << 5
	TCP_ACK = 1 << 4
	TCP_PSH = 1 << 3
	TCP_RST = 1 << 2
	TCP_SYN = 1 << 1
	TCP_FIN = 1 << 0
)

type Tcphdr struct {
	SrcPort  uint16
	DestPort uint16
	Seq      uint32
	Ack      uint32
	Off      uint8
	UrgFlag  bool
	AckFlag  bool
	PshFlag  bool
	RstFlag  bool
	SynFlag  bool
	FinFlag  bool
	Window   uint16
	Chksum   uint16
	UrgPtr   uint16
}

func (tcphdr *Tcphdr) Decode(tcpPkt []byte) (error) {
	if len(tcpPkt) < 20 {
		return errors.New("Invalid tcp pakcet, packet length < basic tcp header length.")
	}

	tcphdr.SrcPort = binary.BigEndian.Uint16(tcpPkt[0:2])
	tcphdr.DestPort = binary.BigEndian.Uint16(tcpPkt[2:4])
	tcphdr.Seq = binary.BigEndian.Uint32(tcpPkt[4:8])
	tcphdr.Ack = binary.BigEndian.Uint32(tcpPkt[8:12])
	offset := binary.BigEndian.Uint16(tcpPkt[12:14])
	tcphdr.Off = uint8((offset & 0xF000) >> 12)
	if offset & TCP_URG != 0 {
		tcphdr.UrgFlag = true
	} else {
		tcphdr.UrgFlag = false
	}
	if offset & TCP_ACK != 0 {
		tcphdr.AckFlag = true
	} else {
		tcphdr.AckFlag = false
	}
	if offset & TCP_PSH != 0 {
		tcphdr.PshFlag = true
	} else {
		tcphdr.PshFlag = false
	}
	if offset & TCP_RST != 0 {
		tcphdr.RstFlag = true
	} else {
		tcphdr.RstFlag = false
	}
	if offset & TCP_SYN != 0 {
		tcphdr.SynFlag = true
	} else {
		tcphdr.SynFlag = false
	}
	if offset & TCP_FIN != 0 {
		tcphdr.FinFlag = true
	} else {
		tcphdr.FinFlag = false
	}
	tcphdr.Window = binary.BigEndian.Uint16(tcpPkt[14:16])
	tcphdr.Chksum = binary.BigEndian.Uint16(tcpPkt[16:18])
	tcphdr.UrgPtr = binary.BigEndian.Uint16(tcpPkt[18:20])

	return nil
}
