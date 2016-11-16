package analyzer

import (
	"github.com/zhengyuli/ntrace/analyzer/http"
	"time"
)

type Analyzer interface {
	Init()
	Proto() (protoName string)
	HandleEstb(timestamp time.Time)
	HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes int, sessionBreakdown interface{})
	HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{})
	HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{})
}

type NewAnalyzerFunc func() Analyzer
type DetectProtoFunc func(payload []byte, fromClient bool, timestamp time.Time) (proto string)

var newAnalyzerFuncs map[string]NewAnalyzerFunc
var detectProtoFuncs []DetectProtoFunc

func init() {
	newAnalyzerFuncs = make(map[string]NewAnalyzerFunc)
	detectProtoFuncs = make([]DetectProtoFunc, 0)

	// Register HTTP Analyzer
	newAnalyzerFuncs[http.ProtoName] = func() Analyzer {
		a := new(http.Analyzer)
		a.Init()

		return a
	}
	detectProtoFuncs = append(detectProtoFuncs, http.DetectProto)
}

func GetAnalyzer(proto string) Analyzer {
	if newAnalyzerFunc := newAnalyzerFuncs[proto]; newAnalyzerFunc != nil {
		return newAnalyzerFunc()
	}

	return nil
}

func DetectProto(payload []byte, fromClient bool, timestamp time.Time) (parseBytes int, proto string) {
	for i := 0; i < len(newAnalyzerFuncs); i++ {
		if proto := detectProtoFuncs[i](payload, fromClient, timestamp); proto != "" {
			return len(payload), proto
		}
	}

	return len(payload), ""
}
