package ipdefrag

import (
	"container/list"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zhengyuli/ntrace/layers"
	"time"
)

const (
	// IPv4MaximumLength IPv4 packet maximum length.
	IPv4MaximumLength = 65535
	// IPv4MaximumFragmentOffset IPv4 packet maximum fragment offset.
	IPv4MaximumFragmentOffset = (IPv4MaximumLength - 20) / 8
	// IPv4MaximumFragmentListSize IPv4 packet maximum fragment list size.
	IPv4MaximumFragmentListSize = 8
)

// FragmentList IPv4 fragment list.
type FragmentList struct {
	IPv4Frag                IPv4Fragment
	Fragments               list.List
	Highest                 uint16
	Current                 uint16
	LastReceived            bool
	LastSeen                time.Time
	FragmentListListElement *list.Element
}

func (f *FragmentList) insert(ip *layers.IPv4) (*layers.IPv4, error) {
	fragOffset := ip.FragOffset * 8
	if fragOffset >= f.Highest {
		f.Fragments.PushBack(ip)
	} else {
		for e := f.Fragments.Front(); e != nil; e = e.Next() {
			frag, _ := e.Value.(*layers.IPv4)
			if ip.FragOffset <= frag.FragOffset {
				log.Debug("IPv4 defrag: insert IPv4 fragment %d before existing IP fragment %d.",
					fragOffset, frag.FragOffset*8)
				f.Fragments.InsertBefore(ip, e)
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

	log.Debug("IPv4 defrag: IPv4 fragments list length: %d, highest: %d, current: %d.",
		f.Fragments.Len(), f.Highest, f.Current)

	if !ip.MF {
		f.LastReceived = true
	}
	if f.LastReceived && f.Highest == f.Current {
		return f.glue(ip)
	}
	return nil, nil
}

func (f *FragmentList) glue(ip *layers.IPv4) (*layers.IPv4, error) {
	var final []byte
	var currentOffset uint16

	log.Debug("IPv4 defrag: start gluing IPv4 fragments.")
	for e := f.Fragments.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		if frag.FragOffset*8 == currentOffset {
			log.Debug("IPv4 defrag: glue IPv4 fragment - %d.", frag.FragOffset*8)
			final = append(final, frag.Payload...)
			currentOffset = currentOffset + frag.Length - uint16(frag.IHL*4)
		} else if frag.FragOffset*8 < currentOffset {
			// Overlapping fragment
			startAt := currentOffset - frag.FragOffset*8
			log.Debug("IPv4 defrag: glue overlapping IPv4 fragment, starting at %d.", startAt)
			if startAt < frag.Length-uint16(frag.IHL*4) {
				final = append(final, frag.Payload[startAt:]...)
				currentOffset = frag.FragOffset*8 + frag.Length - uint16(frag.IHL*4)
			}
		} else {
			log.Debug("IPv4 defrag: find hole while gluing, expected frag offset - %d, actual offset - %d.",
				currentOffset, frag.FragOffset*8)
			return nil, fmt.Errorf("find hole while gluing")
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

// IPv4Fragment IPv4 fragment.
type IPv4Fragment struct {
	SrcIP string
	DstIP string
	ID    uint16
}

// Equal check IPv4Fragment is equal.
func (i IPv4Fragment) Equal(n IPv4Fragment) bool {
	if i.SrcIP == n.SrcIP && i.DstIP == n.DstIP && i.ID == n.ID {
		return true
	}

	return false
}

// IPv4Defragmenter IPv4 defragmenter to defrag IPv4 fragment.
type IPv4Defragmenter struct {
	ipFlows          map[IPv4Fragment]*FragmentList
	FragmentListList list.List
}

// DefragIPv4 IPv4 defragment entry.
func (d *IPv4Defragmenter) DefragIPv4(ip *layers.IPv4) (*layers.IPv4, error) {
	// Check if need to defrag
	if ip.DF || (!ip.MF && ip.FragOffset == 0) {
		return ip, nil
	}

	// Perfom security checks
	if ip.FragOffset > IPv4MaximumFragmentOffset {
		return nil, fmt.Errorf("invalid (too big) IPv4 fragment offset - %d > %d",
			ip.FragOffset, IPv4MaximumFragmentOffset)
	}
	if ip.FragOffset*8+ip.Length > IPv4MaximumLength {
		return nil, fmt.Errorf("invalid (too big) IPv4 fragment Length  - %d > %d",
			ip.FragOffset*8+ip.Length, IPv4MaximumLength)
	}

	// Get an ip fragment
	log.Debug("IPv4 defrag: got an IPv4 fragment with ID=%d, FragOffset=%d, DF=%t, MF=%t.",
		uint16(ip.ID), ip.FragOffset, ip.DF, ip.MF)

	ipf := IPv4Fragment{
		SrcIP: ip.SrcIP.String(),
		DstIP: ip.DstIP.String(),
		ID:    ip.ID,
	}

	// Remove expired fragment list if any
	for d.FragmentListList.Len() > 0 {
		fragmentList := d.FragmentListList.Front().Value.(*FragmentList)
		if fragmentList.IPv4Frag.Equal(ipf) ||
			time.Now().Before(fragmentList.LastSeen.Add(time.Second*30)) {
			break
		}

		delete(d.ipFlows, fragmentList.IPv4Frag)
		d.FragmentListList.Remove(fragmentList.FragmentListListElement)
	}

	fl, exist := d.ipFlows[ipf]
	if !exist {
		log.Debug("IPv4 defrag: create new IPv4 fragments list.")
		fl = new(FragmentList)
		fl.IPv4Frag = ipf
		d.ipFlows[ipf] = fl
	} else {
		d.FragmentListList.Remove(fl.FragmentListListElement)
	}
	out, err := fl.insert(ip)

	if out != nil || err != nil || fl.Fragments.Len() >= IPv4MaximumFragmentListSize {
		delete(d.ipFlows, ipf)
		if fl.Fragments.Len() >= IPv4MaximumFragmentListSize {
			err = fmt.Errorf("IPv4 fragments list hits its maximum "+
				"size=%d without success, flushing the list", IPv4MaximumFragmentListSize)
		}
	} else {
		fl.FragmentListListElement = d.FragmentListList.PushBack(fl)
	}

	return out, err
}

// NewIPv4Defragmenter returns a new IPv4Defragmenter.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	return &IPv4Defragmenter{
		ipFlows: make(map[IPv4Fragment]*FragmentList),
	}
}
