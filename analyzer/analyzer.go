package analyzer

import (
	"bitbucket.org/zhengyuli/ntrace/analyzer/dumy"
	"time"
)

type Analyzer interface {
	Init()
	Proto() string
	HandleEstb(timestamp time.Time)
	HandleData(payload *[]byte, fromClient bool, timestamp time.Time) (sessionDone bool)
	HandleReset(fromClient bool, timestamp time.Time) (sessionDone bool)
	HandleFin(fromClient bool, timestamp time.Time) (sessionDone bool)
}

func GetAnalyzer(proto string) Analyzer {
	var analyzer Analyzer

	switch proto {
	default:
		analyzer = new(dumy.DumyAnalyzer)
		analyzer.Init()
		return analyzer
	}
}
