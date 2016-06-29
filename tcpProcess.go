package main

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	"bitbucket.org/zhengyuli/ntrace/tcpassembly"
	log "github.com/Sirupsen/logrus"
	"hash/fnv"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"
)

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

func tcpProcessService(wg *sync.WaitGroup, state *RunState) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("TcpProcessService run with error: %s.", err)
			state.stop()
		} else {
			log.Info("TcpProcessService exit normally... .. .")
		}
		wg.Done()
	}()

	timer := time.NewTimer(time.Second)
	for !state.stopped() {
		timer.Reset(time.Second)
		select {
		case context := <-tcpDispatchChannel:
			layerType := context.NetworkDecoder.NextLayerType()
			decoder := context.NetworkDecoder.NextLayerDecoder()
			if decoder == layers.NullDecoder {
				log.Errorf("No proper decoder for %s.", layerType.Name())
				continue
			}
			if err := decoder.Decode(context.NetworkDecoder.LayerPayload()); err != nil {
				log.Errorf("Decode %s error: %s.", layerType.Name(), err)
				continue
			}

			context.TransportDecoder = decoder
			// TODO: IPv6 support
			ip := context.NetworkDecoder.(*layers.IPv4)
			tcp := context.TransportDecoder.(*layers.TCP)
			hash := tcpDispatchHash(ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
			tcpAssemblyChannels[hash%uint32(runtime.NumCPU())] <- context

		case <-timer.C:
			break
		}
	}
}

func tcpAssemblyService(index int, wg *sync.WaitGroup, state *RunState) {
	assembler := tcpassembly.NewAssembler()

	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("TcpAssemblyService run with error: %s.", err)
			state.stop()
		} else {
			log.Info("TcpAssemblyService exit normally... .. .")
		}
		log.Infof("tcpAssemblyService: %d got %d tcp streams.", index, assembler.Count)
		wg.Done()
	}()

	timer := time.NewTimer(time.Second)
	for !state.stopped() {
		timer.Reset(time.Second)
		select {
		case context := <-tcpAssemblyChannels[index]:
			assembler.Assemble(context.NetworkDecoder, context.TransportDecoder, context.Time)

		case <-timer.C:
			break
		}
	}
}
