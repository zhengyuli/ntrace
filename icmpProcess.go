package main

import (
	"bitbucket.org/zhengyuli/ntrace/layers"
	log "github.com/Sirupsen/logrus"
	"sync"
	"time"
)

func icmpProcessService(wg *sync.WaitGroup, state *RunState) {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("IcmpProcessService run with error: %s.", err)
			state.stop()
		} else {
			log.Info("IcmpProcessService exit normally... .. .")
		}
		wg.Done()
	}()

	timer := time.NewTimer(time.Second)
	for !state.stopped() {
		timer.Reset(time.Second)
		select {
		case context := <-icmpDispatchChannel:
			layerType := context.NetworkDecoder.NextLayerType()
			decoder := layers.NewDecoder(layerType)
			if decoder == layers.NullDecoder {
				log.Errorf("No proper decoder for %s.", layerType)
				continue
			}
			if err := decoder.Decode(context.NetworkDecoder.LayerPayload()); err != nil {
				log.Errorf("Decode %s error: %s.", layerType, err)
				continue
			}
			log.Infof("%s", decoder)

		case <-timer.C:
			break
		}
	}
}
