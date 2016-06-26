package appservice

import (
	"net"
	"testing"
)

func TestAppServiceManager(t *testing.T) {
	as1 := AppService{
		Proto: "HTTP",
		IP:    net.IPv4(1, 1, 1, 1),
		Port:  80,
	}

	as2 := AppService{
		Proto: "HTTP",
		IP:    net.IPv4(2, 2, 2, 2),
		Port:  80,
	}

	asm := NewAppServiceManager()
	asm.Add(&as1)
	asm.Add(&as1)
	asm.Add(&as2)

	as := asm.Get(as1.IP, as1.Port)
	if as != &as1 {
		t.Error("AppService: get AppService with error.")
	}

	as = asm.Get(as2.IP, as2.Port)
	if as != &as2 {
		t.Error("AppService: get AppService with error.")
	}
}
