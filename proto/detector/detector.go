package detector

import (
	"fmt"
	"github.com/zhengyuli/ntrace/proto"
	"github.com/zhengyuli/ntrace/proto/detector/http"
	"sync"
)

// DetectProtoFunc proto detect function.
type DetectProtoFunc func(payload []byte, fromClient bool) (detected bool)

// Detector proto detector.
type Detector struct {
	ProtoName string
	Detect    DetectProtoFunc
}

// detectProtoFuncs all registered proto detectors.
var protoDetectors []Detector

var detectedProtosLock sync.RWMutex
var detectedProtos map[string]string

// AddProto add TCP application layer proto name by ip and port.
func AddProto(protoName string, ip string, port uint16) {
	detectedProtosLock.Lock()
	defer detectedProtosLock.Unlock()

	detectedProtos[fmt.Sprintf("%s:%d", ip, port)] = protoName
}

// GetProto get TCP application layer proto name by ip and port.
func GetProto(ip string, port uint16) string {
	detectedProtosLock.Lock()
	defer detectedProtosLock.Unlock()

	return detectedProtos[fmt.Sprintf("%s:%d", ip, port)]
}

// DetectProto loop all registered proto detect functions to find the proper analyzer.
func DetectProto(payload []byte, fromClient bool) (parseBytes uint, protoName string) {
	for i := 0; i < len(protoDetectors); i++ {
		if protoDetectors[i].Detect(payload, fromClient) {
			return uint(len(payload)), protoDetectors[i].ProtoName
		}
	}

	return uint(len(payload)), ""
}

func init() {
	// Register HTTP detector
	protoDetectors = append(
		protoDetectors,
		Detector{
			ProtoName: proto.HTTPProtoName,
			Detect:    http.DetectProto})

	detectedProtos = make(map[string]string)
}
