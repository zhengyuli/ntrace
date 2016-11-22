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

func GetProto(ip string, port uint16) (proto string, err error) {
	appServicesLock.RLock()
	defer appServicesLock.RUnlock()

	key := fmt.Sprintf("%s:%d", ip, port)
	if as, ok := appServices[key]; ok {
		return as.proto, nil
	}

	return "", fmt.Errorf("AppService %s:%d has not been added", ip, port)
}
