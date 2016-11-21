package tcp

import (
	log "github.com/Sirupsen/logrus"
	"time"
)

const (
	ProtoName = "TCP"
)

type sessionState uint16

const (
	sessionInit sessionState = iota
	sessionDataExchanging
	sessionComplete
)

func (s sessionState) String() string {
	switch s {
	case sessionInit:
		return "TCPSessionInit"

	case sessionDataExchanging:
		return "TCPSessionDataExchanging"

	case sessionComplete:
		return "TCPSessionComplete"

	default:
		return "InvalidTCPSessionState"
	}
}

type session struct {
	resetFlag        bool
	State            sessionState
	DataExchangeSize uint
	SessionBeginTime time.Time
	SessionEndTime   time.Time
}

func (s session) session2Breakdown() *SessionBreakdown {
	sb := new(SessionBreakdown)

	if s.resetFlag {
		sb.SessionState = "Reset:" + s.State.String()
	} else {
		sb.SessionState = s.State.String()
	}
	sb.DataExchangeSize = s.DataExchangeSize
	if s.SessionEndTime.After(s.SessionBeginTime) {
		sb.SessionLatency = uint(s.SessionEndTime.Sub(s.SessionBeginTime).Nanoseconds() / 1000000)
	}

	return sb
}

type SessionBreakdown struct {
	SessionState     string `json:"tcp_session_state"`
	DataExchangeSize uint   `json:"tcp_data_exchange_size"`
	SessionLatency   uint   `json:"tcp_session_latency"`
}

type Analyzer struct {
	session session
}

func (a *Analyzer) Init() {
	log.Debug("TCP Analyzer: init.")
}

func (a *Analyzer) Proto() (protoName string) {
	return ProtoName
}

func (a *Analyzer) HandleEstb(timestamp time.Time) {
	log.Debug("TCP Analyzer: HandleEstb.")

	a.session.SessionBeginTime = timestamp
}

func (a *Analyzer) HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes int, sessionBreakdown interface{}) {
	if fromClient {
		log.Debugf("TCP Analyzer: receive %d bytes data from client.", len(payload))
	} else {
		log.Debugf("TCP Analyzer: receive %d bytes data from server.", len(payload))
	}

	a.session.State = sessionDataExchanging
	a.session.DataExchangeSize += uint(len(payload))

	return len(payload), nil
}

func (a *Analyzer) HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("TCP Analyzer: HandleReset from client.")
	} else {
		log.Debug("TCP Analyzer: HandleReset from server.")
	}

	a.session.resetFlag = true
	a.session.State = sessionComplete
	a.session.SessionEndTime = timestamp

	return a.session.session2Breakdown()
}

func (a *Analyzer) HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("TCP Analyzer: HandleFin from client.")
	} else {
		log.Debug("TCP Analyzer: HandleFin from server.")
	}

	oldSessionEndTime := a.session.SessionEndTime
	a.session.SessionEndTime = timestamp

	if oldSessionEndTime.After(a.session.SessionBeginTime) {
		a.session.State = sessionComplete
		return a.session.session2Breakdown()
	}

	return nil
}

func DetectProto(payload []byte, fromClient bool, timestamp time.Time) (proto string) {
	return ""
}
