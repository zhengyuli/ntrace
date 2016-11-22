package appservice

import (
	"net"
	"testing"
)

func TestAppService(t *testing.T) {
	ip1 := net.IPv4(1, 1, 1, 1).String()
	ip2 := net.IPv4(2, 2, 2, 2).String()

	Add("HTTP", ip1, 80)
	Add("HTTP", ip1, 80)
	Add("HTTP", ip2, 80)
	Add("TCP", ip2, 81)

	proto, _ := GetProto(ip1, 80)
	if proto != "HTTP" {
		t.Error("AppService: get AppService with error.")
	}

	proto, _ = GetProto(ip2, 80)
	if proto != "HTTP" {
		t.Error("AppService: get AppService with error.")
	}

	proto, _ = GetProto(ip2, 81)
	if proto != "TCP" {
		t.Error("AppService: get AppService with error.")
	}
}
