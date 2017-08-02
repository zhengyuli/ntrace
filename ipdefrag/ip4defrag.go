package ipdefrag

import (
	"container/list"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/zhengyuli/ntrace/layers"
)

const (
	// IPv4MaximumLength IPv4 packet maximum length.
	IPv4MaximumLength = 65535
	// IPv4MaximumFragmentOffset IPv4 packet maximum fragment offset.
	IPv4MaximumFragmentOffset = (IPv4MaximumLength - 20) / 8
	// IPv4MaximumFragmentListSize IPv4 packet maximum fragment list size.
	IPv4MaximumFragmentListSize = 8
)

// IPv4FragmentID IPv4 fragment ID, which will be used to trace the defragment
// process of IPv4 fragments.
type IPv4FragmentID struct {
	SrcIP string
	DstIP string
	ID    uint16
}

// Equal return true if IPv4FragmentID is equal else return false.
func (i IPv4FragmentID) Equal(n IPv4FragmentID) bool {
	if i.SrcIP == n.SrcIP && i.DstIP == n.DstIP && i.ID == n.ID {
		return true
	}

	return false
}

// IPv4FragmentAggregator IPv4 fragment list.
type IPv4FragmentAggregator struct {
	FragmentID   IPv4FragmentID
	Fragments    list.List
	Highest      uint16
	Current      uint16
	LastReceived bool
	LastSeen     time.Time
	Node         *list.Element
}

func (f *IPv4FragmentAggregator) insert(ip *layers.IPv4) (*layers.IPv4, error) {
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

func (f *IPv4FragmentAggregator) glue(ip *layers.IPv4) (*layers.IPv4, error) {
	var finalPayload []byte
	var currentOffset uint16

	log.Debug("IPv4 defrag: start gluing IPv4 fragments.")
	for e := f.Fragments.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		if frag.FragOffset*8 == currentOffset {
			log.Debug("IPv4 defrag: glue IPv4 fragment - %d.", frag.FragOffset*8)
			finalPayload = append(finalPayload, frag.Payload...)
			currentOffset = currentOffset + frag.Length - uint16(frag.IHL*4)
		} else if frag.FragOffset*8 < currentOffset {
			// Overlapping fragment
			startAt := currentOffset - frag.FragOffset*8
			log.Debug("IPv4 defrag: glue overlapping IPv4 fragment, starting at %d.", startAt)
			if startAt < frag.Length-uint16(frag.IHL*4) {
				finalPayload = append(finalPayload, frag.Payload[startAt:]...)
				currentOffset = frag.FragOffset*8 + frag.Length - uint16(frag.IHL*4)
			}
		} else {
			log.Debug("IPv4 defrag: find hole while gluing, expected frag offset - %d, actual offset - %d.",
				currentOffset, frag.FragOffset*8)
			return nil, fmt.Errorf("find hole while gluing")
		}
	}

	return &layers.IPv4{
		Base:       layers.Base{Payload: finalPayload},
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Length:     f.Highest,
		ID:         0,
		MF:         false,
		DF:         true,
		FragOffset: 0,
		TTL:        ip.TTL,
		Protocol:   ip.Protocol,
		Checksum:   ip.Checksum,
		SrcIP:      ip.SrcIP,
		DstIP:      ip.DstIP,
		Options:    ip.Options,
	}, nil
}

// IPv4Defragmenter IPv4 defragmenter to defrag IPv4 fragment.
type IPv4Defragmenter struct {
	FragmentAggregators     map[IPv4FragmentID]*IPv4FragmentAggregator
	FragmentAggregatorsList list.List
}

// DefragIPv4 IPv4 defragment entry.
func (d *IPv4Defragmenter) DefragIPv4(ip *layers.IPv4) (*layers.IPv4, error) {
	// If packet is not fragmented return directly
	if ip.DF || (!ip.MF && ip.FragOffset == 0) {
		return ip, nil
	}

	if ip.FragOffset > IPv4MaximumFragmentOffset {
		return nil, fmt.Errorf("invalid (too big) IPv4 fragment offset - %d > %d",
			ip.FragOffset, IPv4MaximumFragmentOffset)
	}
	if ip.FragOffset*8+ip.Length > IPv4MaximumLength {
		return nil, fmt.Errorf("invalid (too big) IPv4 fragment Length  - %d > %d",
			ip.FragOffset*8+ip.Length, IPv4MaximumLength)
	}

	log.Debug("IPv4 defrag: got an IPv4 fragment with ID=%d, FragOffset=%d, DF=%t, MF=%t.",
		uint16(ip.ID), ip.FragOffset, ip.DF, ip.MF)

	ipfID := IPv4FragmentID{
		SrcIP: ip.SrcIP.String(),
		DstIP: ip.DstIP.String(),
		ID:    ip.ID,
	}

	// Remove expired fragment list if any
	for d.FragmentAggregatorsList.Len() > 0 {
		fragmentList := d.FragmentAggregatorsList.Front().Value.(*IPv4FragmentAggregator)
		if fragmentList.FragmentID.Equal(ipfID) ||
			time.Now().Before(fragmentList.LastSeen.Add(time.Second*30)) {
			break
		}

		delete(d.FragmentAggregators, fragmentList.FragmentID)
		d.FragmentAggregatorsList.Remove(fragmentList.Node)
	}

	fl, exist := d.FragmentAggregators[ipfID]
	if !exist {
		log.Debug("IPv4 defrag: create new IPv4 fragments list.")
		fl = new(IPv4FragmentAggregator)
		fl.FragmentID = ipfID
		d.FragmentAggregators[ipfID] = fl
	} else {
		d.FragmentAggregatorsList.Remove(fl.Node)
	}
	out, err := fl.insert(ip)

	if out != nil || err != nil || fl.Fragments.Len() >= IPv4MaximumFragmentListSize {
		delete(d.FragmentAggregators, ipfID)
		if fl.Fragments.Len() >= IPv4MaximumFragmentListSize {
			err = fmt.Errorf("IPv4 fragments list hits its maximum "+
				"size=%d without success, flushing the list", IPv4MaximumFragmentListSize)
		}
	} else {
		fl.Node = d.FragmentAggregatorsList.PushBack(fl)
	}

	return out, err
}

// NewIPv4Defragmenter create a new IPv4Defragmenter.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	return &IPv4Defragmenter{
		FragmentAggregators: make(map[IPv4FragmentID]*IPv4FragmentAggregator),
	}
}
