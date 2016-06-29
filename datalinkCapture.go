package main

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	"bitbucket.org/zhengyuli/ntrace/sniffer"
	"bitbucket.org/zhengyuli/ntrace/sniffer/driver"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"sync"
)

func datalinkCaptureService(netDev string, wg *sync.WaitGroup, state *RunState) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("DatalinkCaptureService run with error: %s.", err)
			state.stop()
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
	for !state.stopped() {
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

			context := new(layers.DecodeContext)
			context.Time = pkt.Time
			context.DatalinkDecoder = decoder

			switch decoder.NextLayerType() {
			case layers.ProtocolFamilyIPv4,
				layers.EthernetTypeIPv4:
				ipDispatchChannel <- context

			default:
				log.Errorf("Unsupported next layer type: %s.", decoder.NextLayerType().Name())
			}
		}
	}
}
