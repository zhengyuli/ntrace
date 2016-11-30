package http

// DetectProto HTTP proto detect function.
func DetectProto(payload []byte, fromClient bool) (detected bool) {
	preLen := 0
	payloadLen := len(payload)

	if fromClient {
		switch {
		// Normal
		case payloadLen >= 7 && string(payload[:7]) == "DELETE ":
			preLen = 7

		case payloadLen >= 4 && string(payload[:4]) == "GET ":
			preLen = 4

		case payloadLen >= 5 && string(payload[:5]) == "HEAD ":
			preLen = 5

		case payloadLen >= 4 && string(payload[:4]) == "PUT ":
			preLen = 4

			// Pathological
		case payloadLen >= 8 && string(payload[:8]) == "CONNECT ":
			preLen = 8

		case payloadLen >= 8 && string(payload[:8]) == "OPTIONS ":
			preLen = 8

		case payloadLen >= 6 && string(payload[:6]) == "TRACE ":
			preLen = 6

			// WebDAV
		case payloadLen >= 5 && string(payload[:5]) == "COPY ":
			preLen = 5

		case payloadLen >= 5 && string(payload[:5]) == "LOCK ":
			preLen = 5

		case payloadLen >= 6 && string(payload[:6]) == "MKCOL ":
			preLen = 6

		case payloadLen >= 5 && string(payload[:5]) == "MOVE ":
			preLen = 5

		case payloadLen >= 9 && string(payload[:9]) == "PROPFIND ":
			preLen = 9

		case payloadLen >= 10 && string(payload[:10]) == "PROPPATCH ":
			preLen = 10

		case payloadLen >= 7 && string(payload[:7]) == "SEARCH ":
			preLen = 7

		case payloadLen >= 7 && string(payload[:7]) == "UNLOCK ":
			preLen = 7

			// Subversion
		case payloadLen >= 7 && string(payload[:7]) == "REPORT ":
			preLen = 7

		case payloadLen >= 11 && string(payload[:11]) == "MKACTIVITY ":
			preLen = 11

		case payloadLen >= 9 && string(payload[:9]) == "CHECKOUT ":
			preLen = 9

		case payloadLen >= 6 && string(payload[:6]) == "MERGE ":
			preLen = 6

			// Upnp
		case payloadLen >= 8 && string(payload[:8]) == "MSEARCH ":
			preLen = 8

		case payloadLen >= 7 && string(payload[:7]) == "NOTIFY ":
			preLen = 7

		case payloadLen >= 10 && string(payload[:10]) == "SUBSCRIBE ":
			preLen = 10

		case payloadLen >= 12 && string(payload[:12]) == "UNSUBSCRIBE ":
			preLen = 12

			// RFC-5789
		case payloadLen >= 6 && string(payload[:6]) == "PATCH ":
			preLen = 7

		case payloadLen >= 6 && string(payload[:6]) == "PURGE ":
			preLen = 7

		default:
			preLen = 0
		}

		if preLen > 0 {
			for i := preLen; i < payloadLen-1; i++ {
				if string(payload[i]) == "\r" &&
					string(payload[i+1]) == "\n" &&
					(string(payload[i-8]) == "HTTP/1.0" || string(payload[i-8]) == "HTTP/1.1") {
					return true
				}
			}
		}
	} else {
		if payloadLen >= 8 &&
			(string(payload[:8]) == "HTTP/1.0" || string(payload[:8]) == "HTTP/1.1") {
			return true
		}
	}

	return false
}
