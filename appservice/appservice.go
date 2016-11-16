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

var ignoredAppServiceslock sync.RWMutex
var ignoredAppServices map[string]bool

func init() {
	appServices = make(map[string]*appService)
	ignoredAppServices = make(map[string]bool)
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

	return "", fmt.Errorf("AppService %s:%d has not been added.", ip, port)
}

func AddIgnored(ip string, port uint16) {
	ignoredAppServiceslock.Lock()
	defer ignoredAppServiceslock.Unlock()

	key := fmt.Sprintf("%s:%d", ip, port)
	ignoredAppServices[key] = true
}

func IsIgnored(ip string, port uint16) bool {
	ignoredAppServiceslock.Lock()
	defer ignoredAppServiceslock.Unlock()

	key := fmt.Sprintf("%s:%d", ip, port)
	return ignoredAppServices[key]
}
