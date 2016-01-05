package main

import (
	"errors"
	"capture/pcap"
)

// Pcap configs
const (
	PCAP_MAX_CAPTURE_LENGTH = 65535
	PCAP_CAPTURE_TIMEOUT = 500
	PCAP_CAPTURE_IN_PROMISC = true
)

// Pcap descriptor for sniff
var pcapDescForSniff *pcap.Pcap
// Datalink type for sniff
var datalinkTypeForSniff int

// Pcap descriptor for proto detect
var pcapDescForProtoDetect *pcap.Pcap
// Datalink type for proto detect
var datalinkTypeForProtoDetect int

func newPcapInterfaceDesc(pcapInterface string) (pcapDesc *pcap.Pcap, err error) {
	pcapDesc, err = pcap.Openlive(pcapInterface, PCAP_MAX_CAPTURE_LENGTH,
		PCAP_CAPTURE_IN_PROMISC, PCAP_CAPTURE_TIMEOUT)
	return
}

func getStatsForSniff() (stat *pcap.Stat, err error) {
    stat, err = pcapDescForSniff.Getstats()
	return
}

func getStatsForProtoDetect() (stat *pcap.Stat, err error) {
    stat, err = pcapDescForProtoDetect.Getstats()
	return
}

func updateNetDevFilterForSniff(filter string) (err error) {
	return pcapDescForSniff.Setfilter(filter)
}

func updateNetDevFilterForProtoDetect(filter string) (err error) {
	return pcapDescForProtoDetect.Setfilter(filter)
}

func initNetDev() (err error) {
	pcapDescForSniff, err = newPcapInterfaceDesc(globalProperties.netDev)
	if err != nil {
		return
	}

	pcapDescForProtoDetect, err = newPcapInterfaceDesc(globalProperties.netDev)
	if err != nil {
		pcapDescForSniff.Close()
		return
	}

	datalinkTypeForSniff = pcapDescForSniff.Datalink()
	datalinkTypeForProtoDetect = pcapDescForProtoDetect.Datalink()

	if datalinkTypeForSniff < 0 || datalinkTypeForProtoDetect < 0 {
		pcapDescForSniff.Close()
		pcapDescForProtoDetect.Close()
		return errors.New("Invalid datalink type")
	}

	return nil;
}

func destroyNetDev() {
	if pcapDescForSniff != nil {
		pcapDescForSniff.Close()
	}

	if pcapDescForProtoDetect != nil {
		pcapDescForProtoDetect.Close()
	}
}
