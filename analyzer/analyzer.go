package analyzer

import (
	"bitbucket.org/zhengyuli/ntrace/analyzer/dumy"
	"bitbucket.org/zhengyuli/ntrace/analyzer/http"
	"time"
)

type Analyzer interface {
	Init()
	Proto() string
	HandleEstb(timestamp time.Time)
	HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes int, sessionBreakdown interface{})
	HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{})
	HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{})
}

func GetAnalyzer(proto string) Analyzer {
	var analyzer Analyzer

	switch proto {
	case http.ProtoName:
		analyzer = new(http.Analyzer)

	default:
		analyzer = new(dumy.Analyzer)
	}

	analyzer.Init()
	return analyzer
}
