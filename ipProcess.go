package main

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	log "github.com/Sirupsen/logrus"
	"sync"
	"time"
)

func ipProcessService(wg *sync.WaitGroup, state *RunState) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("IpProcessService run with error: %s.", err)
			state.stop()
		} else {
			log.Info("IpProcessService exit normally... .. .")
		}
		wg.Done()
	}()

	timer := time.NewTimer(time.Second)
	for !state.stopped() {
		timer.Reset(time.Second)
		select {
		case context := <-ipDispatchChannel:
			layerType := context.DatalinkDecoder.NextLayerType()
			decoder := layers.NewDecoder(layerType)
			if decoder == layers.NullDecoder {
				log.Errorf("No proper decoder for %s.", layerType)
				continue
			}
			if err := decoder.Decode(context.DatalinkDecoder.LayerPayload()); err != nil {
				log.Errorf("Decode %s error: %s.", layerType, err)
				continue
			}

			context.NetworkDecoder = decoder

			switch decoder.NextLayerType() {
			case layers.IPv4ProtocolICMP:
				icmpDispatchChannel <- context

			case layers.IPv4ProtocolTCP:
				tcpDispatchChannel <- context

			default:
				log.Errorf("Unsupported next layer type: %s.", decoder.NextLayerType())
			}

		case <-timer.C:
			break
		}
	}
}
