package analyzer

import (
	"github.com/zhengyuli/ntrace/proto"
	"github.com/zhengyuli/ntrace/proto/analyzer/http"
	"github.com/zhengyuli/ntrace/proto/analyzer/tcp"
	"time"
)

// Analyzer interface of TCP application layer protocol analyzer.
type Analyzer interface {
	Init()
	HandleEstb(timestamp time.Time)
	HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes uint, sessionBreakdown interface{})
	HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{})
	HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{})
}

// NewAnalyzerFunc create new analyzer function.
type NewAnalyzerFunc func() Analyzer

// newAnalyzerFuncs all registered proto analyzer creation funcs.
var newAnalyzerFuncs map[string]NewAnalyzerFunc

// GetAnalyzer get a new analyzer by ip and port.
func GetAnalyzer(protoName string) Analyzer {
	if newAnalyzerFunc := newAnalyzerFuncs[protoName]; newAnalyzerFunc != nil {
		return newAnalyzerFunc()
	}

	return nil
}

func init() {
	newAnalyzerFuncs = make(map[string]NewAnalyzerFunc)

	// Register HTTP Analyzer
	newAnalyzerFuncs[proto.HTTPProtoName] = func() Analyzer {
		a := new(http.Analyzer)
		a.Init()

		return a
	}

	// Register TCP Analyzer
	newAnalyzerFuncs[proto.TCPProtoName] = func() Analyzer {
		a := new(tcp.Analyzer)
		a.Init()

		return a
	}
}
