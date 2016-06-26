package fasthash

import (
	"net"
	"testing"
)

func TestTcpDispatchHash(t *testing.T) {
	srcIP := net.IPv4(1, 1, 1, 1)
	srcPort := uint16(8000)
	dstIP := net.IPv4(1, 1, 1, 1)
	dstPort := uint16(80)

	h1 := TcpDispatchHash(srcIP, srcPort, dstIP, dstPort)
	h2 := TcpDispatchHash(dstIP, dstPort, srcIP, srcPort)
	if h1 != h2 {
		t.Error("Wrong hash.")
	}
}
