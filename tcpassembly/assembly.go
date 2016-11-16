package tcpassembly

import (
	"container/list"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zhengyuli/ntrace/analyzer"
	"github.com/zhengyuli/ntrace/appservice"
	"github.com/zhengyuli/ntrace/layers"
	"math"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"
)

var TinyTcpPayloadBytes = 32

func init() {
	if payloadBytes, err := strconv.Atoi(os.Getenv("TINY_TCP_PAYLOAD_BYTES")); err != nil {
		TinyTcpPayloadBytes = payloadBytes
	}
}

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
	State              TcpState
	Seq                uint32
	Ack                uint32
	ExpRcvSeq          uint32
	RecvData           []byte
	TotalRecvDataBytes uint32
	Pages              list.List
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

func (s StreamState) String() string {
	switch s {
	case StreamConnecting:
		return "StreamConnecting"

	case StreamConnected:
		return "StreamConnected"

	case StreamDataExchanging:
		return "StreamDataExchanging"

	case StreamClosing:
		return "StreamClosing"

	case StreamClosingTimeout:
		return "StreamClosingTimeout"

	case StreamClosed:
		return "StreamClosed"

	case StreamClosedAbnormally:
		return "StreamClosedAbnormally"

	case StreamClosedExceedMaxCount:
		return "StreamClosedExceedMaxCount"

	case StreamResetByClientBeforeConn:
		return "StreamResetByClientBeforeConn"

	case StreamResetByServerBeforeConn:
		return "StreamResetByServerBeforeConn"

	case StreamResetByClientAferConn:
		return "StreamResetByClientAferConn"

	case StreamResetByServerAferConn:
		return "StreamResetByServerAferConn"

	default:
		return "InvalidStreamState"
	}
}

type Stream struct {
	// Tcp connection info
	Addr                      Tuple4
	State                     StreamState
	Client                    HalfStream
	Server                    HalfStream
	HandshakeSyncTime         time.Time
	HandshakeSyncRetryTime    time.Time
	HandshakeSyncAckTime      time.Time
	HandshakeSyncAckRetryTime time.Time
	HandshakeEstabTime        time.Time
	HandshakeSyncRetries      uint
	HandshakeSyncAckRetries   uint
	MSS                       uint

	// Tcp data exchanging info
	Client2ServerBytes                uint
	Server2ClientBytes                uint
	Client2ServerPackets              uint
	Server2ClientPackets              uint
	Client2ServerTinyPackets          uint
	Server2ClientTinyPackets          uint
	Client2ServerRetransmittedPackets uint
	Server2ClientRetransmittedPackets uint
	Client2ServerOutOfOrderPackets    uint
	Server2ClientOutOfOrderPackets    uint
	Client2ServerDupAcks              uint
	Server2ClientDupAcks              uint
	ClientZeroWindows                 uint
	ServerZeroWindows                 uint

	// Tcp application layer analyzer
	Analyzer analyzer.Analyzer

	// Other
	StreamsListElement        *list.Element
	ClosingExpireTime         time.Time
	ClosingStreamsListElement *list.Element
}

func (s *Stream) ResetDataExhangingInfo() {
	s.Client2ServerBytes = 0
	s.Server2ClientBytes = 0
	s.Client2ServerPackets = 0
	s.Server2ClientPackets = 0
	s.Client2ServerTinyPackets = 0
	s.Server2ClientTinyPackets = 0
	s.Client2ServerRetransmittedPackets = 0
	s.Server2ClientRetransmittedPackets = 0
	s.Client2ServerOutOfOrderPackets = 0
	s.Server2ClientOutOfOrderPackets = 0
	s.Client2ServerDupAcks = 0
	s.Server2ClientDupAcks = 0
	s.ClientZeroWindows = 0
	s.ServerZeroWindows = 0
}

func (s *Stream) Session2Breakdown(appSessionBreakdown interface{}) *SessionBreakdown {
	sb := new(SessionBreakdown)

	sb.Proto = s.Analyzer.Proto()
	sb.Addr = s.Addr.String()
	sb.MSS = s.MSS
	sb.Client2ServerBytes = s.Client2ServerBytes
	sb.Server2ClientBytes = s.Server2ClientBytes
	sb.Client2ServerPackets = s.Client2ServerPackets
	sb.Server2ClientPackets = s.Server2ClientPackets
	sb.Client2ServerTinyPackets = s.Client2ServerTinyPackets
	sb.Server2ClientTinyPackets = s.Server2ClientTinyPackets
	sb.Client2ServerRetransmittedPackets = s.Client2ServerRetransmittedPackets
	sb.Server2ClientRetransmittedPackets = s.Server2ClientRetransmittedPackets
	sb.Client2ServerOutOfOrderPackets = s.Client2ServerOutOfOrderPackets
	sb.Server2ClientOutOfOrderPackets = s.Server2ClientOutOfOrderPackets
	sb.Client2ServerDupAcks = s.Client2ServerDupAcks
	sb.Server2ClientDupAcks = s.Server2ClientDupAcks
	sb.ClientZeroWindows = s.ClientZeroWindows
	sb.ServerZeroWindows = s.ServerZeroWindows
	sb.ApplicationSessionBreakdown = appSessionBreakdown
	// Reset data exchanging info for next application session breakdown
	s.ResetDataExhangingInfo()

	return sb
}

type SessionBreakdown struct {
	Proto                             string      `json:"proto"`
	Addr                              string      `json:"address"`
	MSS                               uint        `json:tcp_mss,omitempty`
	Client2ServerBytes                uint        `json:"tcp_c2s_bytes"`
	Server2ClientBytes                uint        `json:"tcp_s2c_bytes"`
	Client2ServerPackets              uint        `json:"tcp_c2s_packets"`
	Server2ClientPackets              uint        `json:"tcp_s2c_packets"`
	Client2ServerTinyPackets          uint        `json:"tcp_c2s_tiny_packets"`
	Server2ClientTinyPackets          uint        `json:"tcp_s2c_tiny_packets"`
	Client2ServerRetransmittedPackets uint        `json:"tcp_c2s_retransmitted_packets"`
	Server2ClientRetransmittedPackets uint        `json:"tcp_s2c_retransmitted_packets"`
	Client2ServerOutOfOrderPackets    uint        `json:"tcp_c2s_out_of_order_packets"`
	Server2ClientOutOfOrderPackets    uint        `json:"tcp_s2c_out_of_order_packets"`
	Client2ServerDupAcks              uint        `json:"tcp_c2s_duplicate_acks"`
	Server2ClientDupAcks              uint        `json:"tcp_s2c_duplicate_acks"`
	ClientZeroWindows                 uint        `json:"tcp_client_zero_windows"`
	ServerZeroWindows                 uint        `json:"tcp_server_zero_windows"`
	ApplicationSessionBreakdown       interface{} `json:"application_session_breakdown"`
}

type Assembler struct {
	Count              uint32
	Streams            map[Tuple4]*Stream
	StreamsList        list.List
	ClosingStreamsList list.List
	SessionBreakdowns  []interface{}
}

func (a *Assembler) handleEstb(stream *Stream, timestamp time.Time) {
	log.Debugf("Tcp assembly: tcp connection %s is connected.", stream.Addr)

	stream.State = StreamConnected
	stream.Client.State = TcpEstablished
	stream.Server.State = TcpEstablished
	stream.HandshakeEstabTime = timestamp

	if stream.Analyzer != nil {
		stream.Analyzer.HandleEstb(timestamp)
	}
}

func (a *Assembler) handleData(stream *Stream, snd *HalfStream, rcv *HalfStream, timestamp time.Time) {
	var direction Direction
	if snd == &stream.Client {
		direction = FromClient
	} else {
		direction = FromServer
	}

	log.Debugf("Tcp assembly: tcp connection %s get %d bytes data %s.", stream.Addr, len(rcv.RecvData), direction)

	var parseBytes int
	if stream.Analyzer != nil {
		var appSessionBreakdown interface{}

		if direction == FromClient {
			parseBytes, appSessionBreakdown = stream.Analyzer.HandleData(rcv.RecvData, true, timestamp)
		} else {
			parseBytes, appSessionBreakdown = stream.Analyzer.HandleData(rcv.RecvData, false, timestamp)
		}
		rcv.RecvData = rcv.RecvData[parseBytes:]
		rcv.TotalRecvDataBytes += uint32(parseBytes)

		if appSessionBreakdown != nil {
			log.Debugf("Tcp assembly: tcp connection %s generate new session breakdown by Data %s.", stream.Addr, direction)
			a.SessionBreakdowns = append(a.SessionBreakdowns, stream.Session2Breakdown(appSessionBreakdown))
		}
	} else {
		var proto string

		if direction == FromClient {
			parseBytes, proto = analyzer.DetectProto(rcv.RecvData, true, timestamp)
		} else {
			parseBytes, proto = analyzer.DetectProto(rcv.RecvData, false, timestamp)
		}
		rcv.RecvData = rcv.RecvData[parseBytes:]
		rcv.TotalRecvDataBytes += uint32(parseBytes)

		if proto != "" ||
			(rcv.TotalRecvDataBytes+uint32(parseBytes) > 200 && snd.TotalRecvDataBytes > 200) {
			if proto != "" {
				log.Debugf("Tcp assembly: detect recognizable appService=%s:%d-%s.", stream.Addr.DstIP, stream.Addr.DstPort, proto)
				appservice.Add(proto, stream.Addr.DstIP, stream.Addr.DstPort)
			} else {
				log.Debugf("Tcp assembly: detect unrecognizable appService=%s:%d.", stream.Addr.DstIP, stream.Addr.DstPort)
				appservice.AddIgnored(stream.Addr.DstIP, stream.Addr.DstPort)
			}
			a.removeStream(stream)
		}
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
	} else if stream.Analyzer != nil {
		var appSessionBreakdown interface{}
		if direction == FromClient {
			stream.State = StreamResetByClientAferConn
			appSessionBreakdown = stream.Analyzer.HandleReset(true, timestamp)
		} else {
			stream.State = StreamResetByServerAferConn
			appSessionBreakdown = stream.Analyzer.HandleReset(false, timestamp)
		}
		if appSessionBreakdown != nil {
			log.Debugf("Tcp assembly: tcp connection %s generate new session breakdown by Reset %s.", stream.Addr, direction)
			a.SessionBreakdowns = append(a.SessionBreakdowns, stream.Session2Breakdown(appSessionBreakdown))
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

	if !lazyMode && stream.Analyzer != nil {
		var appSessionBreakdown interface{}
		if direction == FromClient {
			appSessionBreakdown = stream.Analyzer.HandleFin(true, timestamp)
		} else {
			appSessionBreakdown = stream.Analyzer.HandleFin(false, timestamp)
		}
		if appSessionBreakdown != nil {
			log.Debugf("Tcp assembly: tcp connection %s generate new session breakdown by Fin %s.", stream.Addr, direction)
			a.SessionBreakdowns = append(a.SessionBreakdowns, stream.Session2Breakdown(appSessionBreakdown))
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
	var srcIP, dstIP net.IP

	if ip4, ok := ipDecoder.(*layers.IPv4); ok {
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP
	} else {
		log.Errorf("Tcp assembly: unsupported network decoder=%s.", reflect.TypeOf(ipDecoder))
		return nil, FromClient
	}

	stream := a.Streams[Tuple4{
		SrcIP:   srcIP.String(),
		SrcPort: tcp.SrcPort,
		DstIP:   dstIP.String(),
		DstPort: tcp.DstPort}]
	if stream != nil {
		return stream, FromClient
	}

	stream = a.Streams[Tuple4{
		SrcIP:   dstIP.String(),
		SrcPort: tcp.DstPort,
		DstIP:   srcIP.String(),
		DstPort: tcp.SrcPort}]
	if stream != nil {
		return stream, FromServer
	}

	return nil, FromClient
}

func (a *Assembler) addStream(ipDecoder layers.Decoder, tcp *layers.TCP, timestamp time.Time) {
	var srcIP, dstIP net.IP

	if ip4, ok := ipDecoder.(*layers.IPv4); ok {
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP
	} else {
		log.Errorf("Tcp assembly: unsupported network decoder=%s.", reflect.TypeOf(ipDecoder))
		return
	}

	if appservice.IsIgnored(dstIP.String(), tcp.DstPort) {
		return
	}

	addr := Tuple4{
		SrcIP:   srcIP.String(),
		SrcPort: tcp.SrcPort,
		DstIP:   dstIP.String(),
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
		HandshakeSyncTime:      timestamp,
		HandshakeSyncRetryTime: timestamp,
	}
	stream.MSS = tcp.GetMSSOption()
	stream.ResetDataExhangingInfo()

	if proto, err := appservice.GetProto(dstIP.String(), tcp.DstPort); err == nil {
		stream.Analyzer = analyzer.GetAnalyzer(proto)
	}

	if stream.Analyzer != nil || a.StreamsList.Len() < 65536 {
		if stream.Analyzer != nil {
			a.Count++
		}
		a.Streams[addr] = stream
		stream.StreamsListElement = a.StreamsList.PushBack(stream)
	}

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
			if snd == &stream.Client {
				log.Debugf("Tcp assembly: tcp connection %s get retransmited packet FromClient.", stream.Addr)
				stream.Client2ServerRetransmittedPackets++
			} else {
				log.Debugf("Tcp assembly: tcp connection %s get retransmited packet FromServer.", stream.Addr)
				stream.Server2ClientRetransmittedPackets++
			}

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
		if snd == &stream.Client {
			log.Debugf("Tcp assembly: tcp connection %s get out of order packet FromClient.", stream.Addr)
			stream.Client2ServerOutOfOrderPackets++
		} else {
			log.Debugf("Tcp assembly: tcp connection %s get out of order packet FromServer.", stream.Addr)
			stream.Server2ClientOutOfOrderPackets++
		}

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
		// The first packet of tcp three-way handshakes
		if tcp.SYN && !tcp.ACK && !tcp.RST {
			a.addStream(ipDecoder, tcp, timestamp)
		}
		return
	}

	if tcp.SYN {
		// The second packet of tcp three-way handshakes
		if direction == FromServer && tcp.ACK &&
			stream.Client.State == TcpSynSent && stream.Server.State == TcpClosed {
			stream.Server.State = TcpSynReceived
			stream.Server.Seq = tcp.Seq
			stream.Server.Ack = tcp.Ack
			stream.Client.ExpRcvSeq = tcp.Seq + 1
			stream.HandshakeSyncAckTime = timestamp
			stream.HandshakeSyncAckRetryTime = timestamp
			if mss := tcp.GetMSSOption(); mss > 0 && mss < stream.MSS {
				stream.MSS = mss
			}

			return
		}

		// Tcp sync retries
		if direction == FromClient &&
			stream.Client.State == TcpSynSent {
			log.Debugf("Tcp assembly: tcp connection %s handshake with sync retry.", stream.Addr)
			stream.HandshakeSyncRetryTime = timestamp
			stream.HandshakeSyncRetries++
			return
		}

		// Tcp sync/ack retries
		if direction == FromServer &&
			stream.Server.State == TcpSynReceived {
			log.Debugf("Tcp assembly: tcp connection %s handshake with sync/ack retry.", stream.Addr)
			stream.HandshakeSyncAckRetryTime = timestamp
			stream.HandshakeSyncAckRetries++
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
		// The third packet of tcp three-way handshakes
		if direction == FromClient &&
			stream.Client.State == TcpSynSent && stream.Server.State == TcpSynReceived {
			if tcp.Seq != stream.Server.ExpRcvSeq {
				log.Debug("Tcp assembly: unexpected sequence=%d of the third packet of "+
					"tcp three-way handshakes, expected sequence=%d.", tcp.Seq, stream.Server.ExpRcvSeq)
				a.handleCloseAbnormally(stream, timestamp)
				return
			}

			a.handleEstb(stream, timestamp)
		}

		if seqDiff(snd.Ack, tcp.Ack) < 0 {
			snd.Ack = tcp.Ack
		} else if len(tcp.Payload) == 0 {
			// Duplicate Ack packet
			if direction == FromClient {
				stream.Client2ServerDupAcks++
			} else {
				stream.Server2ClientDupAcks++
			}
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

		if len(tcp.Payload) > 0 {
			if direction == FromClient {
				stream.Client2ServerBytes += uint(len(tcp.Payload))
				stream.Client2ServerPackets++
				if tcp.Window == 0 {
					stream.ClientZeroWindows++
				}
			} else {
				stream.Server2ClientBytes += uint(len(tcp.Payload))
				stream.Server2ClientPackets++
				if tcp.Window == 0 {
					stream.ServerZeroWindows++
				}
			}

			if len(tcp.Payload) <= TinyTcpPayloadBytes {
				if direction == FromClient {
					stream.Client2ServerTinyPackets++
				} else {
					stream.Server2ClientTinyPackets++
				}
			}
		}

		a.tcpQueue(stream, snd, rcv, tcp, timestamp)
	}
}

func NewAssembler() *Assembler {
	return &Assembler{
		Streams: make(map[Tuple4]*Stream),
	}
}
