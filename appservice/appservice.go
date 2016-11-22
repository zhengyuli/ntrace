package appservice

import (
	"fmt"
	"sync"
)

type appService struct {
	proto string
	ip    string
	port  uint16
}

var appServicesLock sync.RWMutex
var appServices map[string]*appService

func init() {
	appServices = make(map[string]*appService)
}

// Add add TCP application layer service info.
func Add(proto string, ip string, port uint16) {
	appServicesLock.Lock()
	defer appServicesLock.Unlock()

	key := fmt.Sprintf("%s:%d", ip, port)
	appServices[key] = &appService{
		proto: proto,
		ip:    ip,
		port:  port,
	}
}

// GetProto get TCP application layer service proto name by ip and port.
func GetProto(ip string, port uint16) (proto string, err error) {
	appServicesLock.RLock()
	defer appServicesLock.RUnlock()

	key := fmt.Sprintf("%s:%d", ip, port)
	if as, ok := appServices[key]; ok {
		return as.proto, nil
	}

	return "", fmt.Errorf("AppService %s:%d has not been added", ip, port)
}
