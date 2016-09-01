package main

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	"bitbucket.org/zhengyuli/ntrace/sniffer"
	"bitbucket.org/zhengyuli/ntrace/sniffer/driver"
	"bitbucket.org/zhengyuli/ntrace/tcpassembly"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"hash/fnv"
	"net"
	"os"
	"os/signal"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

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

var (
	netDev   string
	logDir   string
	logFile  string
	logLevel log.Level

	runState RunState
)

func init() {
	netDev = "en0"
	logDir = "/var/log"
	logFile = "ntrace"
	logLevel = log.DebugLevel
}

func setupTeardown() {
	sigChannel := make(chan os.Signal)
	signal.Notify(sigChannel, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigChannel
		runState.stop()
		signal.Stop(sigChannel)
		close(sigChannel)
	}()
}

func setupLogger(logDir string, logFile string, logLevel log.Level) (*os.File, error) {
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

func datalinkCaptureService(netDev string, ipDispatchChannel chan *layers.Packet, wg *sync.WaitGroup) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("DatalinkCaptureService run with error: %s.", err)
			runState.stop()
		} else {
			log.Info("DatalinkCaptureService exit normally... .. .")
		}
		wg.Done()
	}()

	handle, err := sniffer.New(netDev)
	if err != nil {
		panic(err)
	}

	err = handle.SetFilter("tcp or icmp")
	if err != nil {
		panic(err)
	}

	pkt := new(driver.Packet)
	for !runState.stopped() {
		err := handle.NextPacket(pkt)
		if err != nil {
			panic(err)
		}

		if pkt.Data != nil {
			// Filter out incomplete network packet
			if pkt.CapLen != pkt.PktLen {
				log.Warn("Incomplete packet.")
				continue
			}

			layerType := handle.DatalinkType()
			decoder := layerType.NewDecoder()
			if decoder == layers.NullDecoder {
				panic(fmt.Errorf("No proper decoder for %s.", layerType.Name()))
			}
			if err = decoder.Decode(pkt.Data); err != nil {
				log.Errorf("Decode %s error: %s.", layerType.Name(), err)
				continue
			}

			packet := new(layers.Packet)
			packet.Time = pkt.Time
			packet.DatalinkDecoder = decoder

			switch decoder.NextLayerType() {
			case layers.ProtocolFamilyIPv4,
				layers.EthernetTypeIPv4:
				ipDispatchChannel <- packet

			default:
				log.Errorf("Unsupported next layer type: %s.", decoder.NextLayerType().Name())
			}
		}
	}
}

func ipProcessService(
	ipDispatchChannel chan *layers.Packet,
	icmpDispatchChannel chan *layers.Packet,
	tcpDispatchChannel chan *layers.Packet, wg *sync.WaitGroup) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("IpProcessService run with error: %s.", err)
			runState.stop()
		} else {
			log.Info("IpProcessService exit normally... .. .")
		}
		wg.Done()
	}()

	timer := time.NewTimer(time.Second)
	for !runState.stopped() {
		timer.Reset(time.Second)
		select {
		case packet := <-ipDispatchChannel:
			layerType := packet.DatalinkDecoder.NextLayerType()
			decoder := packet.DatalinkDecoder.NextLayerDecoder()
			if decoder == layers.NullDecoder {
				log.Errorf("No proper decoder for %s.", layerType.Name())
				continue
			}
			if err := decoder.Decode(packet.DatalinkDecoder.LayerPayload()); err != nil {
				log.Errorf("Decode %s error: %s.", layerType.Name(), err)
				continue
			}

			packet.NetworkDecoder = decoder

			switch decoder.NextLayerType() {
			case layers.IPv4ProtocolICMP:
				icmpDispatchChannel <- packet

			case layers.IPv4ProtocolTCP:
				tcpDispatchChannel <- packet

			default:
				log.Errorf("Unsupported next layer type: %s.", decoder.NextLayerType())
			}

		case <-timer.C:
			break
		}
	}
}

func icmpProcessService(icmpDispatchChannel chan *layers.Packet, wg *sync.WaitGroup) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("IcmpProcessService run with error: %s.", err)
			runState.stop()
		} else {
			log.Info("IcmpProcessService exit normally... .. .")
		}
		wg.Done()
	}()

	timer := time.NewTimer(time.Second)
	for !runState.stopped() {
		timer.Reset(time.Second)
		select {
		case packet := <-icmpDispatchChannel:
			layerType := packet.NetworkDecoder.NextLayerType()
			decoder := packet.NetworkDecoder.NextLayerDecoder()
			if decoder == layers.NullDecoder {
				log.Errorf("No proper decoder for %s.", layerType.Name())
				continue
			}
			if err := decoder.Decode(packet.NetworkDecoder.LayerPayload()); err != nil {
				log.Errorf("Decode %s error: %s.", layerType.Name(), err)
				continue
			}
			log.Infof("%s", decoder)

		case <-timer.C:
			break
		}
	}
}

func tcpDispatchHash(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) uint32 {
	var data1 []byte
	data1 = append(data1, []byte(srcIP)...)
	data1 = strconv.AppendInt(data1, int64(srcPort), 10)

	var data2 []byte
	data2 = append(data2, []byte(dstIP)...)
	data2 = strconv.AppendInt(data2, int64(dstPort), 10)

	if len(data1) < len(data2) {
		tmp := data1
		data1 = data2
		data2 = tmp
	}

	for i := 0; i < len(data2); i++ {
		data1[i] = data1[i] ^ data2[i]
	}

	sum := fnv.New32()
	sum.Write(data1)
	return sum.Sum32()
}

func tcpProcessService(
	tcpDispatchChannel chan *layers.Packet,
	tcpAssemblyChannels []chan *layers.Packet, wg *sync.WaitGroup) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("TcpProcessService run with error: %s.", err)
			runState.stop()
		} else {
			log.Info("TcpProcessService exit normally... .. .")
		}
		wg.Done()
	}()

	var srcIP, dstIP net.IP
	timer := time.NewTimer(time.Second)

	for !runState.stopped() {
		timer.Reset(time.Second)
		select {
		case packet := <-tcpDispatchChannel:
			layerType := packet.NetworkDecoder.NextLayerType()
			decoder := packet.NetworkDecoder.NextLayerDecoder()
			if decoder == layers.NullDecoder {
				log.Errorf("No proper decoder for %s.", layerType.Name())
				continue
			}
			if err := decoder.Decode(packet.NetworkDecoder.LayerPayload()); err != nil {
				log.Errorf("Decode %s error: %s.", layerType.Name(), err)
				continue
			}

			packet.TransportDecoder = decoder

			if ip4, ok := packet.NetworkDecoder.(*layers.IPv4); ok {
				srcIP = ip4.SrcIP
				dstIP = ip4.DstIP
			} else {
				log.Errorf("Unsupported network decoder: %s.", reflect.TypeOf(packet.NetworkDecoder))
				continue
			}

			tcp := packet.TransportDecoder.(*layers.TCP)
			hash := tcpDispatchHash(srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
			tcpAssemblyChannels[hash%uint32(runtime.NumCPU())] <- packet

		case <-timer.C:
			break
		}
	}
}

func tcpAssemblyService(index int, tcpAssemblyChannel chan *layers.Packet, wg *sync.WaitGroup) {
	assembler := tcpassembly.NewAssembler()

	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("TcpAssemblyService run with error: %s.", err)
			runState.stop()
		} else {
			log.Info("TcpAssemblyService exit normally... .. .")
		}
		log.Infof("tcpAssemblyService: %d got %d tcp streams.", index, assembler.Count)
		wg.Done()
	}()

	timer := time.NewTimer(time.Second)
	for !runState.stopped() {
		timer.Reset(time.Second)
		select {
		case packet := <-tcpAssemblyChannel:
			assembler.Assemble(packet.NetworkDecoder, packet.TransportDecoder, packet.Time)

		case <-timer.C:
			break
		}
	}
}

func main() {
	setupTeardown()

	out, err := setupLogger(logDir, logFile, logLevel)
	if err != nil {
		log.Fatalf("Setup default logger with error: %s.", err)
	}
	defer out.Close()

	log.Debugf("Run with %d cpus.", runtime.NumCPU())
	runtime.GOMAXPROCS(2*runtime.NumCPU() + 1)

	ipDispatchChannel := make(chan *layers.Packet, 100000)
	defer close(ipDispatchChannel)

	icmpDispatchChannel := make(chan *layers.Packet, 100000)
	defer close(icmpDispatchChannel)

	tcpDispatchChannel := make(chan *layers.Packet, 100000)
	defer close(tcpDispatchChannel)

	tcpAssemblyChannels := make([]chan *layers.Packet, runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		tcpAssemblyChannels[i] = make(chan *layers.Packet, 100000)
		defer close(tcpAssemblyChannels[i])
	}

	var wg sync.WaitGroup
	wg.Add(4 + runtime.NumCPU())
	go datalinkCaptureService(netDev, ipDispatchChannel, &wg)
	go ipProcessService(ipDispatchChannel, icmpDispatchChannel, tcpDispatchChannel, &wg)
	go icmpProcessService(icmpDispatchChannel, &wg)
	go tcpProcessService(tcpDispatchChannel, tcpAssemblyChannels, &wg)
	for i := 0; i < runtime.NumCPU(); i++ {
		go tcpAssemblyService(i, tcpAssemblyChannels[i], &wg)
	}

	wg.Wait()
}
