package main

import (
	"bitbucket.org/zhengyuli/ntrace/decode"
	"bitbucket.org/zhengyuli/ntrace/fasthash"
	"bitbucket.org/zhengyuli/ntrace/layers"
	"bitbucket.org/zhengyuli/ntrace/tcpassembly"
	log "github.com/Sirupsen/logrus"
	"runtime"
	"sync"
	"time"
)

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
			decoder := decode.New(layerType)
			if decoder == decode.NullDecoder {
				log.Errorf("No proper decoder for %s.", layerType)
				continue
			}
			if err := decoder.Decode(context.NetworkDecoder.LayerPayload()); err != nil {
				log.Errorf("Decode %s error: %s.", layerType, err)
				continue
			}

			context.TransportDecoder = decoder
			ipDecoder := context.NetworkDecoder.(*layers.IPv4)
			tcpDecoder := context.TransportDecoder.(*layers.TCP)
			hash := fasthash.TcpDispatchHash(
				ipDecoder.SrcIP, tcpDecoder.SrcPort, ipDecoder.DstIP, tcpDecoder.DstPort)
			tcpAssemblyChannels[hash%uint64(runtime.NumCPU())] <- context

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
			assembler.Assemble(context)

		case <-timer.C:
			break
		}
	}
}
