package analyzer

import (
	log "github.com/Sirupsen/logrus"
	"time"
)

type Analyzer interface {
	HandleEstb(timestamp time.Time)
	HandleData(payload *[]byte, fromClient bool, timestamp time.Time) (sessionDone bool)
	HandleReset(fromClient bool, timestamp time.Time) (sessionDone bool)
	HandleFin(fromClient bool, timestamp time.Time) (sessionDone bool)
}

type DumyAnalyzer struct {
}

func (a *DumyAnalyzer) HandleEstb(timestamp time.Time) {
	log.Info("Analyzer: dumy HandleEstb.")
}

func (a *DumyAnalyzer) HandleData(payload *[]byte, fromClient bool, timestamp time.Time) (sessionDone bool) {
	log.Infof("Analyzer: from client=%t get %d bytes data %s", fromClient, len(*payload), string(*payload))
	*payload = (*payload)[len(*payload):]
	return false
}

func (a *DumyAnalyzer) HandleReset(fromClient bool, timestamp time.Time) (sessionDone bool) {
	log.Infof("Analyzer: from client=%t get rest.", fromClient)
	return false
}

func (a *DumyAnalyzer) HandleFin(fromClient bool, timestamp time.Time) (sessionDone bool) {
	log.Infof("Analyzer: from client=%t get fin.", fromClient)
	return false
}
