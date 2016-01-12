package proto

import (
	"time"
	"utils"
)

type ProtoCache struct {
	Time time.Time
	Datalink int
	SrcMac []byte
	DstMac []byte
	Data []byte
}

type ProtoCacheBytes []byte

func (pc *ProtoCache) NetEncode() (pcb ProtoCacheBytes, err error) {
	data, err := utils.Encode(pc)
	return ProtoCacheBytes(data), err
}

func (pcb ProtoCacheBytes) NetDecode() (pc *ProtoCache, err error) {
	pc = new(ProtoCache)
	err = utils.Decode([]byte(pcb), pc)

	return
}
