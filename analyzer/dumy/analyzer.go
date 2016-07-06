package dumy

import (
	log "github.com/Sirupsen/logrus"
	"time"
)

const (
	Proto = "DUMY"
)

type DumyAnalyzer struct {
}

func (da *DumyAnalyzer) Init() {
	log.Info("DumyAnalyzer: dumy init.")
}

func (da *DumyAnalyzer) Proto() string {
	return Proto
}

func (da *DumyAnalyzer) HandleEstb(timestamp time.Time) {
	log.Info("DumyAnalyzer: dumy HandleEstb.")
}

func (da *DumyAnalyzer) HandleData(payload *[]byte, fromClient bool, timestamp time.Time) (sessionDone bool) {
	log.Infof("DumyAnalyzer: from client=%t get %d bytes data %s...", fromClient, len(*payload), string((*payload)[1:32]))
	*payload = (*payload)[len(*payload):]
	return false
}

func (da *DumyAnalyzer) HandleReset(fromClient bool, timestamp time.Time) (sessionDone bool) {
	log.Infof("DumyAnalyzer: from client=%t get rest.", fromClient)
	return false
}

func (da *DumyAnalyzer) HandleFin(fromClient bool, timestamp time.Time) (sessionDone bool) {
	log.Infof("DumyAnalyzer: from client=%t get fin.", fromClient)
	return false
}
