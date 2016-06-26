package appservice

import (
	"bitbucket.org/zhengyuli/ntrace/analyzer"
	"fmt"
	"net"
	"sync"
)

type AppService struct {
	Proto    string
	Analyzer analyzer.Analyzer
	IP       net.IP
	Port     uint16
}

type AppServiceManager struct {
	Lock        sync.RWMutex
	AppServices map[string]*AppService
}

func (asm *AppServiceManager) Add(as *AppService) {
	asm.Lock.Lock()
	defer asm.Lock.Unlock()

	key := fmt.Sprintf("%s:%d", as.IP, as.Port)
	asm.AppServices[key] = as
}

func (asm *AppServiceManager) Get(ip net.IP, port uint16) *AppService {
	asm.Lock.RLock()
	defer asm.Lock.RUnlock()

	key := fmt.Sprintf("%s:%d", ip, port)
	if as, ok := asm.AppServices[key]; ok {
		return as
	}

	return nil
}

func NewAppServiceManager() *AppServiceManager {
	asm := new(AppServiceManager)
	asm.AppServices = make(map[string]*AppService)

	return asm
}
