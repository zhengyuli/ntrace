package ip

import (
	"encoding/binary"
	"errors"
)

const (
	// IP flag mask
	IP_RF = 1 << 15
	IP_DF = 1 << 14
	IP_MF = 1 << 13

	// IP offset mask
	IP_OFFMASK = 0x1FFF
)

const (
	// IP proto
	PROTO_ICMP = 1
	PROTO_TCP  = 6
	PROTO_UDP  = 17
)

type Iphdr struct {
	Ver     uint8
	Ihl     uint8
	Tos     uint8
	Len     uint16
	Id      uint16
	DFlag   bool
	MFlag   bool
	Off     uint16
	Ttl     uint8
	Proto   uint8
	Chksum  uint16
	SrcIp   []byte
	DestIp  []byte
}

func (iphdr *Iphdr) Decode(ipPkt []byte) (error) {
	if len(ipPkt) < 20 {
		return errors.New("Invalid ip pakcet, packet length < basic ip header length.")
	}

	iphdr.Ver = uint8(ipPkt[0]) >> 4
	iphdr.Ihl = uint8(ipPkt[0]) & 0x0F
	iphdr.Tos = uint8(ipPkt[1])
	iphdr.Len = binary.BigEndian.Uint16(ipPkt[2:4])
	iphdr.Id = binary.BigEndian.Uint16(ipPkt[4:6])
	offset := binary.BigEndian.Uint16(ipPkt[6:8])
	if offset & IP_DF != 0 {
		iphdr.DFlag = true
	} else {
		iphdr.DFlag = false
	}
	if offset & IP_MF != 0 {
		iphdr.MFlag = true
	} else {
		iphdr.MFlag = false
	}
	iphdr.Off = offset & IP_OFFMASK
	iphdr.Ttl = uint8(ipPkt[8])
	iphdr.Proto = uint8(ipPkt[9])
	iphdr.Chksum = binary.BigEndian.Uint16(ipPkt[10:12])
	iphdr.SrcIp = ipPkt[12:16]
	iphdr.DestIp = ipPkt[16:20]

	return nil
}
