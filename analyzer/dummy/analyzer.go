package dummy

import (
	log "github.com/Sirupsen/logrus"
	"time"
)

const (
	ProtoName = "DUMMY"
)

type Analyzer struct {
}

func (a *Analyzer) Init() {
	log.Debug("Dummy Analyzer: init.")
}

func (a *Analyzer) Proto() (protoName string) {
	return ProtoName
}

func (a *Analyzer) HandleEstb(timestamp time.Time) {
	log.Debug("Dummy Analyzer: HandleEstb.")
}

func (a *Analyzer) HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes int, sessionBreakdown interface{}) {
	if fromClient {
		log.Debugf("Dummy Analyzer: receive %d bytes data from client.", len(payload))
	} else {
		log.Debugf("Dummy Analyzer: receive %d bytes data from server.", len(payload))
	}

	return len(payload), nil
}

func (a *Analyzer) HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("Dummy Analyzer: HandleReset from client.")
	} else {
		log.Debug("Dummy Analyzer: HandleReset from server.")
	}

	return nil
}

func (a *Analyzer) HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("Dummy Analyzer: HandleFin from client.")
	} else {
		log.Debug("Dummy Analyzer: HandleFin from server.")
	}

	return nil
}

func DetectProto(payload []byte, fromClient bool, timestamp time.Time) (proto string) {
	return ProtoName
}
