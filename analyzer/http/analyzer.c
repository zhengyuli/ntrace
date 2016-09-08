#include "_cgo_export.h"



int onReqMessageBegin_cgo(http_parser* parser) {
    return onReqMessageBegin(parser);
}

int onReqURL_cgo(http_parser* parser, const char *from, size_t length) {
    return onReqURL(parser, (char *)from, length);
}

int onReqHeaderField_cgo(http_parser* parser, const char *from, size_t length) {
    return onReqHeaderField(parser, (char *)from, length);
}

int onReqHeaderValue_cgo(http_parser* parser, const char *from, size_t length) {
    return onReqHeaderValue(parser, (char *)from, length);
}

int onReqHeadersComplete_cgo(http_parser* parser) {
    return onReqHeadersComplete(parser);
}

int onReqBody_cgo(http_parser* parser, const char *from, size_t length) {
    return onReqBody(parser, (char *)from, length);
}

int onReqMessageComplete_cgo(http_parser* parser) {
    return onReqMessageComplete(parser);
}

int onRespMessageBegin_cgo(http_parser* parser) {
    return onRespMessageBegin(parser);
}

int onRespURL_cgo(http_parser* parser, const char *from, size_t length) {
    return onRespURL(parser, (char *)from, length);
}

int onRespHeaderField_cgo(http_parser* parser, const char *from, size_t length) {
    return onRespHeaderField(parser, (char *)from, length);
}

int onRespHeaderValue_cgo(http_parser* parser, const char *from, size_t length) {
    return onRespHeaderValue(parser, (char *)from, length);
}

int onRespHeadersComplete_cgo(http_parser* parser) {
    return onRespHeadersComplete(parser);
}

int onRespBody_cgo(http_parser* parser, const char *from, size_t length) {
    return onRespBody(parser, (char *)from, length);
}

int onRespMessageComplete_cgo(http_parser* parser) {
    return onRespMessageComplete(parser);
}
