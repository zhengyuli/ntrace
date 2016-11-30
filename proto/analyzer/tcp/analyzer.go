package tcp

import (
	log "github.com/Sirupsen/logrus"
	"time"
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
	resetFlag         bool
	State             sessionState
	DataExchangeBytes uint
	BeginTime         time.Time
	CompleteTime      time.Time
}

func (s session) session2Breakdown() *SessionBreakdown {
	sb := new(SessionBreakdown)

	if s.resetFlag {
		sb.SessionState = "Reset:" + s.State.String()
	} else {
		sb.SessionState = s.State.String()
	}
	sb.DataExchangeBytes = s.DataExchangeBytes
	if s.CompleteTime.After(s.BeginTime) {
		sb.SessionLatency = uint(s.CompleteTime.Sub(s.BeginTime).Nanoseconds() / 1000000)
	}

	return sb
}

// SessionBreakdown TCP analyzer session breakdown.
type SessionBreakdown struct {
	SessionState      string `json:"tcp_session_state"`
	DataExchangeBytes uint   `json:"tcp_data_exchange_bytes"`
	SessionLatency    uint   `json:"tcp_session_latency"`
}

// Analyzer TCP analyzer.
type Analyzer struct {
	session session
}

// Init TCP analyzer init function.
func (a *Analyzer) Init() {
	log.Debug("TCP Analyzer: init.")
}

// HandleEstb TCP analyzer handle TCP connection establishment function.
func (a *Analyzer) HandleEstb(timestamp time.Time) {
	log.Debug("TCP Analyzer: HandleEstb.")

	a.session.BeginTime = timestamp
}

// HandleData TCP analyzer handle TCP connection payload function.
func (a *Analyzer) HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes uint, sessionBreakdown interface{}) {
	if fromClient {
		log.Debugf("TCP Analyzer: receive %d bytes data from client.", len(payload))
	} else {
		log.Debugf("TCP Analyzer: receive %d bytes data from server.", len(payload))
	}

	a.session.State = sessionDataExchanging
	a.session.DataExchangeBytes += uint(len(payload))

	return uint(len(payload)), nil
}

// HandleReset TCP analyzer handle TCP connection reset function.
func (a *Analyzer) HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("TCP Analyzer: HandleReset from client.")
	} else {
		log.Debug("TCP Analyzer: HandleReset from server.")
	}

	a.session.resetFlag = true
	a.session.State = sessionComplete
	a.session.CompleteTime = timestamp

	return a.session.session2Breakdown()
}

// HandleFin TCP analyzer handle TCP connection fin function.
func (a *Analyzer) HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("TCP Analyzer: HandleFin from client.")
	} else {
		log.Debug("TCP Analyzer: HandleFin from server.")
	}

	oldCompleteTime := a.session.CompleteTime
	a.session.CompleteTime = timestamp

	if oldCompleteTime.After(a.session.BeginTime) {
		a.session.State = sessionComplete
		return a.session.session2Breakdown()
	}

	return nil
}
