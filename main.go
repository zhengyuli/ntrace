package main

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	log "github.com/Sirupsen/logrus"
	"os"
	"os/signal"
	"path"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	netDev   string
	logDir   string
	logFile  string
	logLevel log.Level

	runState            RunState
	ipDispatchChannel   chan *layers.DecodeContext
	icmpDispatchChannel chan *layers.DecodeContext
	tcpDispatchChannel  chan *layers.DecodeContext
	tcpAssemblyChannels []chan *layers.DecodeContext
)

func init() {
	netDev = "lo0"
	logDir = "/var/log"
	logFile = "ntrace"
	logLevel = log.DebugLevel
}

type RunState uint32

func (rs *RunState) stop() {
	atomic.StoreUint32((*uint32)(rs), 1)
}

func (rs *RunState) stopped() bool {
	s := atomic.LoadUint32((*uint32)(rs))

	if s > 0 {
		return true
	}

	return false
}

func setupDefaultLogger(logDir string, logFile string, logLevel log.Level) (*os.File, error) {
	err := os.MkdirAll(logDir, 0755)

	if err != nil {
		return nil, err
	}

	if path.Ext(logFile) != ".log" {
		logFile = logFile + ".log"
	}
	logFilePath := path.Join(logDir, logFile)
	out, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	log.SetOutput(out)

	log.SetFormatter(
		&log.TextFormatter{
			FullTimestamp:  true,
			DisableColors:  true,
			DisableSorting: true})
	log.SetLevel(logLevel)

	return out, nil
}

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	out, err := setupDefaultLogger(logDir, logFile, logLevel)
	if err != nil {
		log.Fatalf("Setup default logger with error: %s.", err)
	}
	defer out.Close()

	log.Debugf("Run with %d cpus.", runtime.NumCPU())
	runtime.GOMAXPROCS(2*runtime.NumCPU() + 1)

	ipDispatchChannel = make(chan *layers.DecodeContext, 100000)
	defer close(ipDispatchChannel)

	icmpDispatchChannel = make(chan *layers.DecodeContext, 100000)
	defer close(icmpDispatchChannel)

	tcpDispatchChannel = make(chan *layers.DecodeContext, 100000)
	defer close(tcpDispatchChannel)

	tcpAssemblyChannels = make([]chan *layers.DecodeContext, runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		tcpAssemblyChannels[i] = make(chan *layers.DecodeContext, 100000)
		defer close(tcpAssemblyChannels[i])
	}

	var wg sync.WaitGroup
	wg.Add(4 + runtime.NumCPU())
	go datalinkCaptureService(netDev, &wg, &runState)
	go ipProcessService(&wg, &runState)
	go icmpProcessService(&wg, &runState)
	go tcpProcessService(&wg, &runState)
	for i := 0; i < runtime.NumCPU(); i++ {
		go tcpAssemblyService(i, &wg, &runState)
	}

	for !runState.stopped() {
		select {
		case <-sigChan:
			runState.stop()
			goto exit

		case <-time.After(time.Second):
			break
		}
	}

exit:
	wg.Wait()
}
