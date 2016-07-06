package tcpassembly

import (
	"bitbucket.org/zhengyuli/ntrace/analyzer"
	"bitbucket.org/zhengyuli/ntrace/analyzer/dumy"
	"bitbucket.org/zhengyuli/ntrace/layers"
	"container/list"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"math"
	"time"
)

func seqDiff(x, y uint32) int {
	if x > math.MaxUint32-math.MaxUint32/4 && y < math.MaxUint32/4 {
		return int(int64(x) - int64(y) - math.MaxUint32)
	} else if x < math.MaxUint32/4 && y > math.MaxUint32-math.MaxUint32/4 {
		return int(int64(x) + math.MaxUint32 - int64(y))
	}

	return int(int64(x) - int64(y))
}

type Direction uint8

const (
	FromClient Direction = iota
	FromServer
)

func (d Direction) String() string {
	if d == FromClient {
		return "FromClient"
	}

	return "FromServer"
}

type TcpState uint16

const (
	TcpSynSent TcpState = iota
	TcpSynReceived
	TcpEstablished
	TcpFinSent
	TcpFinConfirmed
	TcpClosing
	TcpClosed
)

type Tuple4 struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

func (t Tuple4) String() string {
	return fmt.Sprintf("%s:%d-%s:%d", t.SrcIP, t.SrcPort, t.DstIP, t.DstPort)
}

type Page struct {
	Seq      uint32
	Ack      uint32
	URG, FIN bool
	Urgent   uint16
	Payload  []byte
}

type HalfStream struct {
	State     TcpState
	Seq       uint32
	Ack       uint32
	ExpRcvSeq uint32
	RecvData  []byte
	Pages     list.List
}

type StreamState uint16

const (
	StreamConnecting StreamState = iota
	StreamConnected
	StreamDataExchanging
	StreamClosing
	StreamClosingTimeout
	StreamClosed
	StreamClosedAbnormally
	StreamClosedExceedMaxCount
	StreamResetByClientBeforeConn
	StreamResetByServerBeforeConn
	StreamResetByClientAferConn
	StreamResetByServerAferConn
)

type Stream struct {
	Addr                      Tuple4
	State                     StreamState
	Client                    HalfStream
	Server                    HalfStream
	StreamsListElement        *list.Element
	ClosingExpireTime         time.Time
	ClosingStreamsListElement *list.Element
	Analyzer                  analyzer.Analyzer
}

type Assembler struct {
	Count              uint32
	Streams            map[Tuple4]*Stream
	StreamsList        list.List
	ClosingStreamsList list.List
}

func (a *Assembler) handleEstb(stream *Stream, timestamp time.Time) {
	log.Debugf("Tcp assembly: tcp connection %s connect.", stream.Addr)

	stream.Client.State = TcpEstablished
	stream.Server.State = TcpEstablished
	stream.State = StreamConnected
	stream.Analyzer.HandleEstb(timestamp)
}

func (a *Assembler) handleData(stream *Stream, snd *HalfStream, rcv *HalfStream, timestamp time.Time) {
	var direction Direction
	if snd == &stream.Client {
		direction = FromClient
	} else {
		direction = FromServer
	}

	log.Debugf("Tcp assembly: tcp connection %s get %d bytes data %s.", stream.Addr, len(rcv.RecvData), direction)

	var sessionDone bool
	if direction == FromClient {
		sessionDone = stream.Analyzer.HandleData(&rcv.RecvData, true, timestamp)
	} else {
		sessionDone = stream.Analyzer.HandleData(&rcv.RecvData, false, timestamp)
	}
	if sessionDone {
		log.Debug("Tcp assembly: handle data session done.")
	}
}

func (a *Assembler) handleReset(stream *Stream, snd *HalfStream, rcv *HalfStream, timestamp time.Time) {
	var direction Direction
	if snd == &stream.Client {
		direction = FromClient
	} else {
		direction = FromServer
	}

	log.Warnf("Tcp assembly: tcp connection %s reset %s.", stream.Addr, direction)

	if stream.State == StreamConnecting {
		if direction == FromClient {
			stream.State = StreamResetByClientBeforeConn
		} else {
			stream.State = StreamResetByServerBeforeConn
		}
	} else {
		var sessionDone bool
		if direction == FromClient {
			stream.State = StreamResetByClientAferConn
			sessionDone = stream.Analyzer.HandleReset(true, timestamp)
		} else {
			stream.State = StreamResetByServerAferConn
			sessionDone = stream.Analyzer.HandleReset(false, timestamp)
		}
		if sessionDone {
			log.Debug("Tcp assembly: handle reset session done.")
		}
	}

	a.removeStream(stream)
}

func (a *Assembler) handleFin(stream *Stream, snd *HalfStream, rcv *HalfStream, timestamp time.Time, lazyMode bool) {
	var direction Direction
	if snd == &stream.Client {
		direction = FromClient
	} else {
		direction = FromServer
	}

	log.Debugf("Tcp assembly: tcp connection %s get fin packet %s in lazyMode=%t.", stream.Addr, direction, lazyMode)

	if !lazyMode {
		snd.State = TcpFinSent
	}
	stream.State = StreamClosing
	a.addClosingStream(stream, timestamp)

	if !lazyMode {
		var sessionDone bool
		if direction == FromClient {
			sessionDone = stream.Analyzer.HandleFin(true, timestamp)
		} else {
			sessionDone = stream.Analyzer.HandleFin(false, timestamp)
		}
		if sessionDone {
			log.Debug("Tcp assembly: handle fin session done.")
		}
	}
}

func (a *Assembler) handleClose(stream *Stream, timestamp time.Time) {
	log.Debugf("Tcp assembly: tcp connection %s close normally.", stream.Addr)

	stream.State = StreamClosed
	a.removeStream(stream)
}

func (a *Assembler) handleCloseAbnormally(stream *Stream, timestamp time.Time) {
	log.Errorf("Tcp assembly: tcp connection %s close abnormally.", stream.Addr)

	stream.State = StreamClosedAbnormally
	a.removeStream(stream)
}

func (a *Assembler) handleCloseExceedMaxCount(stream *Stream, timestamp time.Time) {
	log.Warnf("Tcp assembly: tcp connection %s close exceed max count.", stream.Addr)

	stream.State = StreamClosedExceedMaxCount
	a.removeStream(stream)
}

func (a *Assembler) handleClosingTimeout(stream *Stream, timestamp time.Time) {
	log.Errorf("Tcp assembly: tcp connection %s close timeout.", stream.Addr)

	stream.State = StreamClosingTimeout
	a.removeStream(stream)
}

func (a *Assembler) findStream(ipDecoder layers.Decoder, tcp *layers.TCP) (*Stream, Direction) {
	// TODO: IPv6 support
	ip := ipDecoder.(*layers.IPv4)

	stream := a.Streams[Tuple4{
		SrcIP:   ip.SrcIP.String(),
		SrcPort: tcp.SrcPort,
		DstIP:   ip.DstIP.String(),
		DstPort: tcp.DstPort}]
	if stream != nil {
		return stream, FromClient
	}

	stream = a.Streams[Tuple4{
		SrcIP:   ip.DstIP.String(),
		SrcPort: tcp.DstPort,
		DstIP:   ip.SrcIP.String(),
		DstPort: tcp.SrcPort}]
	if stream != nil {
		return stream, FromServer
	}

	return nil, FromClient
}

func (a *Assembler) addStream(ipDecoder layers.Decoder, tcp *layers.TCP, timestamp time.Time) {
	// TODO: IPv6 support
	ip := ipDecoder.(*layers.IPv4)

	addr := Tuple4{
		SrcIP:   ip.SrcIP.String(),
		SrcPort: tcp.SrcPort,
		DstIP:   ip.DstIP.String(),
		DstPort: tcp.DstPort}
	stream := &Stream{
		Addr:  addr,
		State: StreamConnecting,
		Client: HalfStream{
			State:    TcpSynSent,
			Seq:      tcp.Seq,
			Ack:      tcp.Ack,
			RecvData: make([]byte, 0, 4096),
		},
		Server: HalfStream{
			State:     TcpClosed,
			ExpRcvSeq: tcp.Seq + 1,
			RecvData:  make([]byte, 0, 4096),
		},
		Analyzer: analyzer.GetAnalyzer(dumy.Proto),
	}
	a.Count++
	a.Streams[addr] = stream
	stream.StreamsListElement = a.StreamsList.PushBack(stream)

	for a.StreamsList.Len() > 65536 {
		stream := a.StreamsList.Front().Value.(*Stream)
		a.handleCloseAbnormally(stream, timestamp)
	}
}

func (a *Assembler) removeStream(stream *Stream) {
	delete(a.Streams, stream.Addr)
	a.StreamsList.Remove(stream.StreamsListElement)
	if stream.ClosingStreamsListElement != nil {
		a.ClosingStreamsList.Remove(stream.ClosingStreamsListElement)
	}
}

func (a *Assembler) addClosingStream(stream *Stream, timestamp time.Time) {
	stream.ClosingExpireTime = timestamp.Add(time.Second * 30)

	if stream.ClosingStreamsListElement != nil {
		a.ClosingStreamsList.Remove(stream.ClosingStreamsListElement)
	}
	stream.ClosingStreamsListElement = a.ClosingStreamsList.PushBack(stream)
}

func (a *Assembler) checkClosingStream(timestamp time.Time) {
	for a.ClosingStreamsList.Len() > 0 {
		stream := a.ClosingStreamsList.Front().Value.(*Stream)
		if timestamp.Before(stream.ClosingExpireTime) {
			break
		}

		a.handleClosingTimeout(stream, timestamp)
	}
}

func (a *Assembler) addFromPage(stream *Stream, snd *HalfStream, rcv *HalfStream, page *Page, timestamp time.Time) {
	if page.URG {
		if seqDiff(page.Seq+uint32(page.Urgent-1), rcv.ExpRcvSeq) >= 0 {
			rcv.RecvData = append(
				rcv.RecvData,
				page.Payload[seqDiff(rcv.ExpRcvSeq, page.Seq):page.Urgent-1]...)
			rcv.RecvData = append(
				rcv.RecvData,
				page.Payload[page.Urgent:]...)
		} else {
			rcv.RecvData = append(
				rcv.RecvData,
				page.Payload[seqDiff(rcv.ExpRcvSeq, page.Seq):]...)
		}
	} else {
		rcv.RecvData = append(
			rcv.RecvData,
			page.Payload[seqDiff(rcv.ExpRcvSeq, page.Seq):]...)
	}

	rcv.ExpRcvSeq = page.Seq + uint32(len(page.Payload))
	if page.FIN {
		rcv.ExpRcvSeq++
	}

	if page.FIN {
		a.handleFin(stream, snd, rcv, timestamp, false)
	}
}

func (a *Assembler) tcpQueue(stream *Stream, snd *HalfStream, rcv *HalfStream, tcp *layers.TCP, timestamp time.Time) {
	page := &Page{
		Seq:     tcp.Seq,
		Ack:     tcp.Ack,
		URG:     tcp.URG,
		FIN:     tcp.FIN,
		Urgent:  tcp.Urgent,
		Payload: tcp.Payload,
	}

	if seqDiff(tcp.Seq, rcv.ExpRcvSeq) <= 0 {
		endSeq := tcp.Seq + uint32(len(tcp.Payload))
		if tcp.FIN {
			endSeq++
		}

		if seqDiff(endSeq, rcv.ExpRcvSeq) <= 0 {
			log.Debugf("Tcp assembly: tcp connection %s get retransmited packet.", stream.Addr)
			return
		}

		a.addFromPage(stream, snd, rcv, page, timestamp)
		for e := rcv.Pages.Front(); e != nil; {
			if seqDiff(e.Value.(*Page).Seq, rcv.ExpRcvSeq) > 0 {
				break
			}
			a.addFromPage(stream, snd, rcv, e.Value.(*Page), timestamp)
			tmp := e.Next()
			rcv.Pages.Remove(e)
			e = tmp
		}

		if len(rcv.RecvData) > 0 {
			a.handleData(stream, snd, rcv, timestamp)
		}
	} else {
		var e *list.Element
		for e = rcv.Pages.Front(); e != nil; e = e.Next() {
			if seqDiff(e.Value.(*Page).Seq, tcp.Seq) > 0 {
				rcv.Pages.InsertBefore(page, e)
				break
			}
		}
		if e == nil {
			rcv.Pages.PushBack(page)
		}

		if tcp.FIN {
			a.handleFin(stream, snd, rcv, timestamp, true)
		}
	}
}

func (a *Assembler) Assemble(ipDecoder layers.Decoder, tcpDecoder layers.Decoder, timestamp time.Time) {
	tcp := tcpDecoder.(*layers.TCP)
	stream, direction := a.findStream(ipDecoder, tcp)
	if stream == nil {
		// The first packet of tcp three handshakes
		if tcp.SYN && !tcp.ACK && !tcp.RST {
			a.addStream(ipDecoder, tcp, timestamp)
		}
		return
	}

	if tcp.SYN {
		// The second packet of tcp three handshakes
		if direction == FromServer && tcp.ACK &&
			stream.Client.State == TcpSynSent && stream.Server.State == TcpClosed {
			stream.Server.State = TcpSynReceived
			stream.Server.Seq = tcp.Seq
			stream.Server.Ack = tcp.Ack
			stream.Client.ExpRcvSeq = tcp.Seq + 1
			return
		}

		// Tcp sync retries
		if direction == FromClient &&
			stream.Client.State == TcpSynSent {
			log.Debug("tmp - Tcp syn retries.")
			return
		}

		// Tcp sync/ack retries
		if direction == FromServer &&
			stream.Server.State == TcpSynReceived {
			log.Debug("tmp - Tcp syn/ack retries.")
			return
		}

		// Unlikely, invalid packet with syn
		a.handleCloseAbnormally(stream, timestamp)
		return
	}

	var snd, rcv *HalfStream
	if direction == FromClient {
		snd = &stream.Client
		rcv = &stream.Server
	} else {
		snd = &stream.Server
		rcv = &stream.Client
	}
	snd.Seq = tcp.Seq

	// Tcp rset packet
	if tcp.RST {
		a.handleReset(stream, snd, rcv, timestamp)
		return
	}

	if tcp.ACK {
		// The third packet of tcp three handshakes
		if direction == FromClient &&
			stream.Client.State == TcpSynSent && stream.Server.State == TcpSynReceived {
			if tcp.Seq != stream.Server.ExpRcvSeq {
				log.Debug("Tcp assembly: unexpected sequence=%d of the third packet of "+
					"tcp three handshakes, expected sequence=%d.", tcp.Seq, stream.Server.ExpRcvSeq)
				a.handleCloseAbnormally(stream, timestamp)
				return
			}

			a.handleEstb(stream, timestamp)
		}

		if seqDiff(snd.Ack, tcp.Ack) < 0 {
			snd.Ack = tcp.Ack
		} else if len(tcp.Payload) == 0 {
			log.Debug("tmp - Duplicated ack sequence.")
		}

		if rcv.State == TcpFinSent {
			rcv.State = TcpFinConfirmed
		}

		if snd.State == TcpFinConfirmed && rcv.State == TcpFinConfirmed {
			a.handleClose(stream, timestamp)
			return
		}
	}

	if len(tcp.Payload) > 0 || tcp.FIN {
		if stream.State != StreamDataExchanging {
			stream.State = StreamDataExchanging
		}

		if len(tcp.Payload) > 0 && len(tcp.Payload) <= 32 {
			log.Debug("tmp - tiny packets.")
		}

		a.tcpQueue(stream, snd, rcv, tcp, timestamp)
	}
}

func NewAssembler() *Assembler {
	return &Assembler{
		Streams: make(map[Tuple4]*Stream),
	}
}
