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
	HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes int, sessionDone bool)
	HandleReset(fromClient bool, timestamp time.Time) (sessionDone bool)
	HandleFin(fromClient bool, timestamp time.Time) (sessionDone bool)
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
