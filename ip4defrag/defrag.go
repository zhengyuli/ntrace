package ip4defrag

import (
	"container/list"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zhengyuli/ntrace/layers"
	"time"
)

const (
	IPv4MaximumSize            = 65535
	IPv4MaximumFragmentOffset  = (IPv4MaximumSize - 20) / 8
	IPv4MaximumFragmentListLen = 8
)

type fragmentList struct {
	fragments    list.List
	Highest      uint16
	Current      uint16
	LastReceived bool
	LastSeen     time.Time
}

func (f *fragmentList) insert(ip *layers.IPv4) (*layers.IPv4, error) {
	fragOffset := ip.FragOffset * 8
	if fragOffset >= f.Highest {
		f.fragments.PushBack(ip)
	} else {
		for e := f.fragments.Front(); e != nil; e = e.Next() {
			frag, _ := e.Value.(*layers.IPv4)
			if ip.FragOffset <= frag.FragOffset {
				log.Debug("IPv4 defrag: inserting ip fragment %d before existing ip fragment %d.",
					fragOffset, frag.FragOffset*8)
				f.fragments.InsertBefore(ip, e)
				break
			}
		}
	}
	f.LastSeen = time.Now()

	fragLength := ip.Length - uint16(ip.IHL*4)
	f.Current = f.Current + fragLength
	if f.Highest < fragOffset+fragLength {
		f.Highest = fragOffset + fragLength
	}

	log.Debug("IPv4 defrag: ip fragments list length: %d, highest: %d, current: %d.",
		f.fragments.Len(), f.Highest, f.Current)

	if !ip.MF {
		f.LastReceived = true
	}
	if f.LastReceived && f.Highest == f.Current {
		return f.glue(ip)
	}
	return nil, nil
}

func (f *fragmentList) glue(ip *layers.IPv4) (*layers.IPv4, error) {
	var final []byte
	var currentOffset uint16

	log.Debug("IPv4 defrag: Start gluing ip fragments.")
	for e := f.fragments.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		if frag.FragOffset*8 == currentOffset {
			log.Debug("IPv4 defrag: gluing ip fragment - %d.", frag.FragOffset*8)
			final = append(final, frag.Payload...)
			currentOffset = currentOffset + frag.Length - uint16(frag.IHL*4)
		} else if frag.FragOffset*8 < currentOffset {
			// Overlapping fragment
			startAt := currentOffset - frag.FragOffset*8
			log.Debug("IPv4 defrag: gluing overlapping ip fragment, starting at %d.", startAt)
			if startAt < frag.Length-uint16(frag.IHL*4) {
				final = append(final, frag.Payload[startAt:]...)
				currentOffset = frag.FragOffset*8 + frag.Length - uint16(frag.IHL*4)
			}
		} else {
			log.Debug("IPv4 defrag: found hole while gluing, expected frag offset - %d, actual offset - %d.",
				currentOffset, frag.FragOffset*8)
			return nil, fmt.Errorf("found hole while gluing")
		}
	}

	// Construct new IPv4
	out := new(layers.IPv4)
	out.Version = ip.Version
	out.IHL = ip.IHL
	out.TOS = ip.TOS
	out.Length = f.Highest
	out.ID = 0
	out.MF = false
	out.DF = true
	out.FragOffset = 0
	out.TTL = ip.TTL
	out.Protocol = ip.Protocol
	out.Checksum = ip.Checksum
	out.SrcIP = ip.SrcIP
	out.DstIP = ip.DstIP
	out.Options = ip.Options
	out.Payload = final

	return out, nil
}

type ipv4 struct {
	srcIP string
	dstIP string
	id    uint16
}

// IPv4Defragmenter is a struct which embedded a map of
// all fragment/packet.
type IPv4Defragmenter struct {
	ipFlows map[ipv4]*fragmentList
}

func (d *IPv4Defragmenter) DefragIPv4(ip *layers.IPv4) (*layers.IPv4, error) {
	// check if we need to defrag
	if ip.DF || (!ip.MF && ip.FragOffset == 0) {
		return ip, nil
	}

	// perfom security checks
	if ip.FragOffset > IPv4MaximumFragmentOffset {
		return nil, fmt.Errorf("invalid (too big) IPv4 fragment offset - %d > %d",
			ip.FragOffset, IPv4MaximumFragmentOffset)
	}
	if ip.FragOffset*8+ip.Length > IPv4MaximumSize {
		return nil, fmt.Errorf("invalid (too big) IPv4 fragment Length  - %d > %d",
			ip.FragOffset*8+ip.Length, IPv4MaximumSize)
	}

	// Got an ip fragment
	log.Debug("IPv4 defrag: got an ip fragment with ID=%d, FragOffset=%d, DF=%t, MF=%t.",
		uint16(ip.ID), ip.FragOffset, ip.DF, ip.MF)

	ipf := ipv4{
		srcIP: ip.SrcIP.String(),
		dstIP: ip.DstIP.String(),
		id:    ip.ID,
	}

	fl, exist := d.ipFlows[ipf]
	if !exist {
		log.Debug("IPv4 defrag: creating new ip fragments list.")
		fl = new(fragmentList)
		d.ipFlows[ipf] = fl
	}
	out, err := fl.insert(ip)

	if out != nil || err != nil {
		delete(d.ipFlows, ipf)
	}

	// If we hit the maximum frag list len without any defrag success,
	// we just drop everything and raise an error.
	if out == nil && fl.fragments.Len() >= IPv4MaximumFragmentListLen {
		delete(d.ipFlows, ipf)
		err = fmt.Errorf("ip fragments list hits its maximum "+
			"size=%d without success, flushing the list", IPv4MaximumFragmentListLen)
	}

	return out, err
}

// NewIPv4Defragmenter returns a new IPv4Defragmenter
// with an initialized map.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	return &IPv4Defragmenter{
		ipFlows: make(map[ipv4]*fragmentList),
	}
}
