package app_service

import (
    "fmt"
    "sync"
)

type AppService struct {
    Proto string `json:"proto"`
    Ip string    `json:"ip"`
    Port uint16  `json:"port"`
}

type AppServiceManager struct {
    lock *sync.RWMutex
    appServicesMap map[string]AppService
}

func (appSvcManager *AppServiceManager) Add(appSvc AppService) {
    appSvcManager.lock.Lock()
    key := fmt.Sprintf("%s:%d", appSvc.Ip, appSvc.Port)
    appSvcManager.appServicesMap[key] = appSvc
    appSvcManager.lock.Unlock()
}

func (appSvcManager *AppServiceManager) Lookup(ip string, port uint16) (proto string) {
    appSvcManager.lock.RLock()
    key := fmt.Sprintf("%s:%d", ip, port)
    if appSvc, ok := appSvcManager.appServicesMap[key]; ok {
        proto = appSvc.Proto
    } else {
        proto = ""
    }
    appSvcManager.lock.RUnlock()

    return
}

func (appSvcManager *AppServiceManager) Filter() (filter string) {
	appSvcManager.lock.RLock()
	if len(appSvcManager.appServicesMap) == 0 {
		filter = "icmp"
	} else {
		filter = "(("
		for _, appSvc := range(appSvcManager.appServicesMap) {
			filter += fmt.Sprintf("ip host %s or ", appSvc.Ip)
		}
		filter = filter[0:len(filter) - 4] + ") and tcp) or icmp"
	}
	appSvcManager.lock.RUnlock()

	return
}

func NewAppServiceManager() (appSvcManager *AppServiceManager) {
	appSvcManager = new(AppServiceManager)
	appSvcManager.lock = new(sync.RWMutex)
	appSvcManager.appServicesMap = make(map[string]AppService)

	return
}
