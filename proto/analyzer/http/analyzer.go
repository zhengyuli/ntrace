package http

/*
#cgo CFLAGS: -I./http_parser/
#cgo LDFLAGS: -L${SRCDIR}/http_parser -lhttp_parser

#include <http_parser.h>

extern int onReqMessageBegin_cgo(http_parser* parser);
extern int onReqURL_cgo(http_parser* parser, const char *from, size_t length);
extern int onReqHeaderField_cgo(http_parser* parser, const char *from, size_t length);
extern int onReqHeaderValue_cgo(http_parser* parser, const char *from, size_t length);
extern int onReqHeadersComplete_cgo(http_parser* parser);
extern int onReqBody_cgo(http_parser* parser, const char *from, size_t length);
extern int onReqMessageComplete_cgo(http_parser* parser);

extern int onRespMessageBegin_cgo(http_parser* parser);
extern int onRespURL_cgo(http_parser* parser, const char *from, size_t length);
extern int onRespHeaderField_cgo(http_parser* parser, const char *from, size_t length);
extern int onRespHeaderValue_cgo(http_parser* parser, const char *from, size_t length);
extern int onRespHeadersComplete_cgo(http_parser* parser);
extern int onRespBody_cgo(http_parser* parser, const char *from, size_t length);
extern int onRespMessageComplete_cgo(http_parser* parser);
*/
import "C"

import (
	"container/list"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"time"
	"unsafe"
)

type sessionState uint16

const (
	sessionInit sessionState = iota
	requestHeaderBegin
	requestHeaderComplete
	requestBodyBegin
	requestBodyComplete
	responseHeaderBegin
	responseHeaderComplete
	responseBodyBegin
	responseBodyComplete
)

func (s sessionState) String() string {
	switch s {
	case sessionInit:
		return "HTTPSessionInit"

	case requestHeaderBegin:
		return "HTTPRequestHeaderBegin"

	case requestHeaderComplete:
		return "HTTPRequestHeaderComplete"

	case requestBodyBegin:
		return "HTTPRequestBodyBegin"

	case requestBodyComplete:
		return "HTTPRequestBodyComplete"

	case responseHeaderBegin:
		return "HTTPResponseHeaderBegin"

	case responseHeaderComplete:
		return "HTTPResponseHeaderComplete"

	case responseBodyBegin:
		return "HTTPResponseBodyBegin"

	case responseBodyComplete:
		return "HTTPResponseBodyComplete"

	default:
		return "InvalidHTTPSessionState"
	}
}

type header struct {
	name  string
	value string
}

type session struct {
	resetFlag        bool
	state            sessionState
	reqVer           string
	reqMethod        string
	reqURI           string
	reqHeaders       []header
	reqHeaderBytes   uint
	reqBodyBytes     uint
	respVer          string
	respHeaders      []header
	statusCode       uint16
	respHeaderBytes  uint
	respBodyBytes    uint
	reqTime          time.Time
	respBeginTime    time.Time
	respCompleteTime time.Time
}

func (s session) session2Breakdown() *SessionBreakdown {
	sb := new(SessionBreakdown)

	if s.resetFlag {
		sb.SessionState = "Reset:" + s.state.String()
	} else {
		sb.SessionState = s.state.String()
	}

	sb.ReqVer = s.reqVer
	sb.ReqMethod = s.reqMethod
	sb.ReqURI = s.reqURI
	sb.ReqHeaders = make(map[string]string)
	for _, h := range s.reqHeaders {
		sb.ReqHeaders[h.name] = h.value
	}
	sb.ReqHeaderBytes = s.reqHeaderBytes
	sb.ReqBodyBytes = s.reqBodyBytes

	sb.RespVer = s.respVer
	sb.RespHeaders = make(map[string]string)
	for _, h := range s.respHeaders {
		sb.RespHeaders[h.name] = h.value
	}
	sb.StatusCode = s.statusCode
	sb.RespHeaderBytes = s.respHeaderBytes
	sb.RespBodyBytes = s.respBodyBytes

	if s.respBeginTime.After(s.reqTime) {
		sb.ServerLatency = uint(s.respBeginTime.Sub(s.reqTime).Nanoseconds() / 1000000)
	}
	if s.respCompleteTime.After(s.respBeginTime) {
		sb.DownloadLatency = uint(s.respCompleteTime.Sub(s.respBeginTime).Nanoseconds() / 1000000)
	}

	return sb
}

// SessionBreakdown HTTP analyzer session breakdown.
type SessionBreakdown struct {
	SessionState    string            `json:"http_session_state"`
	ReqVer          string            `json:"http_request_version"`
	ReqMethod       string            `json:"http_request_method"`
	ReqURI          string            `json:"http_request_uri"`
	ReqHeaders      map[string]string `json:"http_request_headers"`
	ReqHeaderBytes  uint              `json:"http_request_header_bytes"`
	ReqBodyBytes    uint              `json:"http_request_body_bytes"`
	RespVer         string            `json:"http_response_version"`
	RespHeaders     map[string]string `json:"http_response_headers"`
	StatusCode      uint16            `json:"http_response_status_code"`
	RespHeaderBytes uint              `json:"http_response_header_bytes"`
	RespBodyBytes   uint              `json:"http_response_body_bytes"`
	ServerLatency   uint              `json:"http_server_latency"`
	DownloadLatency uint              `json:"http_download_latency"`
}

//export onReqMessageBegin
func onReqMessageBegin(parser *C.http_parser) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	currSession := new(session)
	currSession.state = requestHeaderBegin
	currSession.reqTime = analyzer.timestamp
	analyzer.sessions.PushBack(currSession)

	return C.int(0)
}

//export onReqURL
func onReqURL(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if back := analyzer.sessions.Back(); back != nil {
		currSession := back.Value.(*session)

		currSession.reqMethod = C.GoString((*C.char)(C.http_method_str(C.enum_http_method(parser.method))))
		currSession.reqURI = C.GoStringN(from, C.int(length))
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onReqHeaderField
func onReqHeaderField(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if back := analyzer.sessions.Back(); back != nil {
		currSession := back.Value.(*session)
		currSession.state = requestHeaderBegin
		headerName := C.GoStringN(from, C.int(length))
		currSession.reqHeaders = append(currSession.reqHeaders, header{name: headerName})
	} else {
		log.Error("http.Analyzer:onReqHeaderField does not find session.")
	}

	return C.int(0)
}

//export onReqHeaderValue
func onReqHeaderValue(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if back := analyzer.sessions.Back(); back != nil {
		currSession := back.Value.(*session)

		headerValue := C.GoStringN(from, C.int(length))
		currSession.reqHeaders[len(currSession.reqHeaders)-1].value = headerValue
	} else {
		log.Error("http.Analyzer:onReqHeaderValue does not find session.")
	}

	return C.int(0)
}

//export onReqHeadersComplete
func onReqHeadersComplete(parser *C.http_parser) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if back := analyzer.sessions.Back(); back != nil {
		currSession := back.Value.(*session)
		currSession.state = requestHeaderComplete

		currSession.reqVer = fmt.Sprintf("HTTP/%d.%d", parser.http_major, parser.http_minor)
		currSession.reqHeaderBytes = uint(parser.nread)
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onReqBody
func onReqBody(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if back := analyzer.sessions.Back(); back != nil {
		currSession := back.Value.(*session)
		currSession.state = requestBodyBegin

		currSession.reqBodyBytes += uint(length)
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onReqMessageComplete
func onReqMessageComplete(parser *C.http_parser) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if back := analyzer.sessions.Back(); back != nil {
		currSession := back.Value.(*session)
		currSession.state = requestBodyComplete
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onRespMessageBegin
func onRespMessageBegin(parser *C.http_parser) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if front := analyzer.sessions.Front(); front != nil {
		currSession := front.Value.(*session)

		currSession.respBeginTime = analyzer.timestamp
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onRespURL
func onRespURL(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	return C.int(0)
}

//export onRespHeaderField
func onRespHeaderField(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if front := analyzer.sessions.Front(); front != nil {
		currSession := front.Value.(*session)
		currSession.state = responseHeaderBegin

		headerName := C.GoStringN(from, C.int(length))
		currSession.respHeaders = append(currSession.respHeaders, header{name: headerName})
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onRespHeaderValue
func onRespHeaderValue(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if front := analyzer.sessions.Front(); front != nil {
		currSession := front.Value.(*session)
		currSession.state = responseHeaderBegin

		headerValue := C.GoStringN(from, C.int(length))
		currSession.respHeaders[len(currSession.respHeaders)-1].value = headerValue
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onRespHeadersComplete
func onRespHeadersComplete(parser *C.http_parser) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if front := analyzer.sessions.Front(); front != nil {
		currSession := front.Value.(*session)
		currSession.state = responseHeaderComplete

		currSession.statusCode = uint16(parser.status_code)
		currSession.respVer = fmt.Sprintf("HTTP/%d.%d", parser.http_major, parser.http_minor)
		currSession.respHeaderBytes = uint(parser.nread)
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onRespBody
func onRespBody(parser *C.http_parser, from *C.char, length C.size_t) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if front := analyzer.sessions.Front(); front != nil {
		currSession := front.Value.(*session)
		currSession.state = responseBodyBegin

		currSession.respBodyBytes += uint(length)
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

//export onRespMessageComplete
func onRespMessageComplete(parser *C.http_parser) C.int {
	analyzer := (*Analyzer)(unsafe.Pointer(uintptr(parser.customData)))

	if front := analyzer.sessions.Front(); front != nil {
		currSession := front.Value.(*session)
		currSession.state = responseBodyComplete

		currSession.respCompleteTime = analyzer.timestamp
	} else {
		log.Error("http.Analyzer:onReqURL does not find session.")
	}

	return C.int(0)
}

// Analyzer HTTP analyzer.
type Analyzer struct {
	timestamp          time.Time
	reqParser          C.http_parser
	reqParserSettings  C.http_parser_settings
	respParser         C.http_parser
	respParserSettings C.http_parser_settings
	sessions           list.List
}

// Init HTTP analyzer init function.
func (a *Analyzer) Init() {
	C.http_parser_init(&a.reqParser, C.HTTP_REQUEST)
	a.reqParser.customData = C.uint64_t(uintptr(unsafe.Pointer(a)))
	a.reqParserSettings.on_message_begin = C.http_cb(unsafe.Pointer(C.onReqMessageBegin_cgo))
	a.reqParserSettings.on_url = C.http_data_cb(unsafe.Pointer(C.onReqURL_cgo))
	a.reqParserSettings.on_header_field = C.http_data_cb(unsafe.Pointer(C.onReqHeaderField_cgo))
	a.reqParserSettings.on_header_value = C.http_data_cb(unsafe.Pointer(C.onReqHeaderValue_cgo))
	a.reqParserSettings.on_headers_complete = C.http_cb(unsafe.Pointer(C.onReqHeadersComplete_cgo))
	a.reqParserSettings.on_body = C.http_data_cb(unsafe.Pointer(C.onReqBody_cgo))
	a.reqParserSettings.on_message_complete = C.http_cb(unsafe.Pointer(C.onReqMessageComplete_cgo))

	C.http_parser_init(&a.respParser, C.HTTP_RESPONSE)
	a.respParser.customData = C.uint64_t(uintptr(unsafe.Pointer(a)))
	a.respParserSettings.on_message_begin = C.http_cb(unsafe.Pointer(C.onRespMessageBegin_cgo))
	a.respParserSettings.on_url = C.http_data_cb(unsafe.Pointer(C.onRespURL_cgo))
	a.respParserSettings.on_header_field = C.http_data_cb(unsafe.Pointer(C.onRespHeaderField_cgo))
	a.respParserSettings.on_header_value = C.http_data_cb(unsafe.Pointer(C.onRespHeaderValue_cgo))
	a.respParserSettings.on_headers_complete = C.http_cb(unsafe.Pointer(C.onRespHeadersComplete_cgo))
	a.respParserSettings.on_body = C.http_data_cb(unsafe.Pointer(C.onRespBody_cgo))
	a.respParserSettings.on_message_complete = C.http_cb(unsafe.Pointer(C.onRespMessageComplete_cgo))

	a.sessions.Init()
}

// HandleEstb HTTP analyzer handle TCP connection establishment function.
func (a *Analyzer) HandleEstb(timestamp time.Time) {
	log.Debug("HTTP Analyzer: HandleEstb.")
}

// HandleData HTTP analyzer handle TCP connection payload function.
func (a *Analyzer) HandleData(payload []byte, fromClient bool, timestamp time.Time) (parseBytes uint, sessionBreakdown interface{}) {
	a.timestamp = timestamp

	var parsed C.size_t
	var sessionElement *list.Element
	var currSession *session
	if fromClient {
		parsed = C.http_parser_execute(&a.reqParser, &a.reqParserSettings, (*C.char)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)))
		if sessionElement = a.sessions.Back(); sessionElement != nil {
			currSession = sessionElement.Value.(*session)
		} else {
			currSession = nil
		}
	} else {
		parsed = C.http_parser_execute(&a.respParser, &a.respParserSettings, (*C.char)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)))
		if sessionElement = a.sessions.Front(); sessionElement != nil {
			currSession = sessionElement.Value.(*session)
		} else {
			currSession = nil
		}
	}

	if currSession == nil || currSession.state != responseBodyComplete {
		return uint(parsed), nil
	}

	a.sessions.Remove(sessionElement)
	return uint(parsed), currSession.session2Breakdown()
}

// HandleReset HTTP analyzer handle TCP connection reset function.
func (a *Analyzer) HandleReset(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("HTTP Analyzer: HandleReset from client.")
	} else {
		log.Debug("HTTP Analyzer: HandleReset from server.")
	}

	if front := a.sessions.Front(); front != nil {
		currSession := *front.Value.(*session)
		if !fromClient && currSession.state == responseBodyBegin {
			currSession.state = responseBodyComplete
			currSession.respCompleteTime = timestamp
		} else {
			currSession.resetFlag = true
		}
		a.sessions.Remove(front)

		return currSession.session2Breakdown()
	}

	return nil
}

// HandleFin HTTP analyzer handle TCP connection fin function.
func (a *Analyzer) HandleFin(fromClient bool, timestamp time.Time) (sessionBreakdown interface{}) {
	if fromClient {
		log.Debug("HTTP Analyzer: HandleFin from client.")
	} else {
		log.Debug("HTTP Analyzer: HandleFin from server.")
	}

	if front := a.sessions.Front(); front != nil && !fromClient {
		if currSession := front.Value.(*session); currSession.state == responseBodyBegin {
			currSession.state = responseBodyComplete
			currSession.respCompleteTime = timestamp
			a.sessions.Remove(front)

			return currSession.session2Breakdown()
		}
	}

	return nil
}
