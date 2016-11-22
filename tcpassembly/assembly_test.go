package tcpassembly

import (
	log "github.com/Sirupsen/logrus"
	"github.com/zhengyuli/ntrace/layers"
	"net"
	"testing"
	"time"
)

var srcIP = net.IP{192, 168, 1, 1}
var srcPort = uint16(1234)
var dstIP = net.IP{10, 66, 128, 1}
var dstPort = uint16(8000)

var addr = Tuple4{
	SrcIP:   srcIP.String(),
	SrcPort: srcPort,
	DstIP:   dstIP.String(),
	DstPort: dstPort,
}

var ipDecoderFromClient = &layers.IPv4{
	SrcIP: srcIP,
	DstIP: dstIP,
}

var ipDecoderFromServer = &layers.IPv4{
	SrcIP: dstIP,
	DstIP: srcIP,
}

var tcpDecoderSyn = &layers.TCP{
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     1,
	SYN:     true,
}

var tcpDecoderSynAck = &layers.TCP{
	SrcPort: 8000,
	DstPort: 1234,
	Seq:     1,
	Ack:     2,
	SYN:     true,
	ACK:     true,
}

var tcpDecoderAck = &layers.TCP{
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     2,
	Ack:     2,
	ACK:     true,
}

var tcpDecoderData1FromClient = &layers.TCP{
	Base: layers.Base{
		Payload: []byte("hello "),
	},
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     2,
	Ack:     2,
	ACK:     true,
}

var tcpDecoderData2FromClient = &layers.TCP{
	Base: layers.Base{
		Payload: []byte("worl#d from client"),
	},
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     8,
	Ack:     2,
	ACK:     true,
	URG:     true,
	Urgent:  5,
}

var tcpDecoderData3FromClient = &layers.TCP{
	Base: layers.Base{
		Payload: []byte("worl#d"),
	},
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     8,
	Ack:     2,
	ACK:     true,
	URG:     true,
	Urgent:  5,
}

var tcpDecoderData4FromClient = &layers.TCP{
	Base: layers.Base{
		Payload: []byte("#d from client!"),
	},
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     12,
	Ack:     2,
	ACK:     true,
	URG:     true,
	Urgent:  1,
}

var tcpDecoderData1FromServer = &layers.TCP{
	Base: layers.Base{
		Payload: []byte("hello "),
	},
	SrcPort: 8000,
	DstPort: 1234,
	Seq:     2,
	Ack:     27,
	ACK:     true,
}

var tcpDecoderData2FromServer = &layers.TCP{
	Base: layers.Base{
		Payload: []byte("world "),
	},
	SrcPort: 8000,
	DstPort: 1234,
	Seq:     8,
	Ack:     27,
	ACK:     true,
}

var tcpDecoderData3FromServer = &layers.TCP{
	Base: layers.Base{
		Payload: []byte("from server"),
	},
	SrcPort: 8000,
	DstPort: 1234,
	Seq:     14,
	Ack:     27,
	ACK:     true,
}

var tcpDecoderFinFromClient = &layers.TCP{
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     27,
	Ack:     25,
	ACK:     true,
	FIN:     true,
}

var tcpDecoderFinAckFromServer = &layers.TCP{
	SrcPort: 8000,
	DstPort: 1234,
	Seq:     25,
	Ack:     28,
	ACK:     true,
}

var tcpDecoderFinFromServer = &layers.TCP{
	SrcPort: 8000,
	DstPort: 1234,
	Seq:     25,
	Ack:     28,
	ACK:     true,
	FIN:     true,
}

var tcpDecoderFinAckFromClient = &layers.TCP{
	SrcPort: 1234,
	DstPort: 8000,
	Seq:     28,
	Ack:     26,
	ACK:     true,
}

type TestAnalyzer struct {
	RecvDataFromClient []byte
	RecvDataFromServer []byte
}

func (a *TestAnalyzer) Init() {
}

func (a *TestAnalyzer) Proto() string {
	return "TEST"
}

func (a *TestAnalyzer) HandleEstb(timestamp time.Time) {
	return
}

func (a *TestAnalyzer) HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes uint, sessionBreakdown interface{}) {
	if fromClient {
		a.RecvDataFromClient = append(a.RecvDataFromClient, (payload)[:]...)
	} else {
		a.RecvDataFromServer = append(a.RecvDataFromServer, (payload)[:]...)
	}

	return uint(len(payload)), nil
}

func (a *TestAnalyzer) HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	return nil
}

func (a *TestAnalyzer) HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	return nil
}

func TestAssembly(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	assembly := NewAssembler()
	timestamp := time.Now()
	assembly.Assemble(ipDecoderFromClient, tcpDecoderSyn, timestamp)
	stream := assembly.Streams[addr]
	if stream == nil {
		t.Error("Tcp assembly: doesn't get the right stream.")
	}
	testAnalyzer := TestAnalyzer{
		RecvDataFromClient: make([]byte, 0),
		RecvDataFromServer: make([]byte, 0),
	}
	stream.Analyzer = &testAnalyzer
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromServer, tcpDecoderSynAck, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromClient, tcpDecoderAck, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromClient, tcpDecoderData1FromClient, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromClient, tcpDecoderData2FromClient, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromClient, tcpDecoderData3FromClient, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromServer, tcpDecoderData3FromServer, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromClient, tcpDecoderData4FromClient, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromServer, tcpDecoderData2FromServer, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromServer, tcpDecoderData1FromServer, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromServer, tcpDecoderData3FromServer, timestamp)
	if string(testAnalyzer.RecvDataFromClient) != "hello world from client!" {
		t.Error("Tcp assembly: get wrong data from client.")
	}
	if string(testAnalyzer.RecvDataFromServer) != "hello world from server" {
		t.Error("Tcp assembly: get wrong data from server.")
	}
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromClient, tcpDecoderFinFromClient, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromServer, tcpDecoderFinAckFromServer, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromServer, tcpDecoderFinFromServer, timestamp)
	timestamp = timestamp.Add(time.Millisecond)
	assembly.Assemble(ipDecoderFromClient, tcpDecoderFinAckFromClient, timestamp)
	if assembly.StreamsList.Len() != 0 {
		t.Errorf("Tcp assembly: stream doesn't close.")
	}
}
