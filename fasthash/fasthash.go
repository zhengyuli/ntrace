package fasthash

import (
	"net"
)

const (
	fnvBasis = 14695981039346656037
	fnvPrime = 1099511628211
)

func fnvHash(s []byte) (h uint64) {
	h = fnvBasis
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime
	}
	return
}

func TcpDispatchHash(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) uint64 {
	h1 := fnvHash([]byte(srcIP))
	h1 ^= uint64(srcPort)
	h1 *= fnvPrime

	h2 := fnvHash([]byte(dstIP))
	h2 ^= uint64(dstPort)
	h2 *= fnvPrime

	return (h1 ^ h2) * fnvPrime
}
