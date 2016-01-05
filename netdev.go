package main

import (
	"errors"
	"github.com/akrennmair/gopcap"
)

// Pcap configs
const (
	PCAP_MAX_CAPTURE_LENGTH = 65535
	PCAP_CAPTURE_TIMEOUT = 500
	PCAP_CAPTURE_IN_PROMISC = 1
)

// Pcap descriptor for sniff
var pcapDescForSniff *gopcap.Pcap
// Datalink type for sniff
var datalinkTypeForSniff int;

// Pcap descriptor for proto detection
var pcapDescForProtoDection *gopcap.Pcap
// Datalink type for proto detection
var datalinkTypeForProtoDetection int

func newPcapFileDesc(pcapFile string) (pcapDesc *pcap.Pcap, err error) {
	pcapDesc, err = pcap.Openoffline(pcapFile)
	return
}

func newPcapInterfaceDesc(pcapInterface string) (pcapDesc *pcap.Pcap, err error) {
	pcapDesc, err = pcap.Openlive(pcapInterface, PCAP_MAX_CAPTURE_LENGTH,
		PCAP_CAPTURE_IN_PROMISC, PCAP_CAPTURE_TIMEOUT)
	return
}

// Get netDev statistic info for sniff
func getNetDevStatisticInfoForSniff() (stat *pcap.Stat, err error) {
    stat, err = pcapDescForSniff.GetStats()
	return
}

// Get netDev statistic info for proto detection
func getNetDevStatisticInfoForProtoDetection() (stat *pcap.Stat, err error) {
    stat, err = pcapDescForProtoDection.GetStats()
	return
}

// Update netDev BPF filter for sniff
func updateNetDevFilterForSniff(filter string) (err error) {
	return pcapDescForSniff.Setfilter(filter)
}

// Update netDev BPF filter for proto detection
func updateNetDevFilterForProtoDetection(filter string) (err error) {
	return pcapDescForProtoDection.Setfilter(filter)
}

func resetNetDevForSniff() (err error) {
	if pcapDescForSniff != nil {
		pcapDescForSniff.Close()
	}

	if getPropertiesSniffLive() {
		tmp, err := newPcapInterfaceDesc(getPropertiesInterface())
	} else {
		tmp, err := newPcapFileDesc(getPropertiesPcapFile())
	}

	if err != nil {
		return
	}

	pcapDescForSniff = tmp
	return
}

func initNetDev() (err error) {
	if getPropertiesSniffLive() {
		pcapDescForSniff, err = newPcapInterfaceDesc(getPropertiesInterface())
		if err != nil {
			return
		}

		pcapDescForProtoDection, err = newPcapInterfaceDesc(getPropertiesInterface())
		if err != nil {
			pcapDescForSniff.Close()
			pcapDescForSniff = nil
			return
		}
	} else {
		pcapDescForSniff, err = newPcapFileDesc(getPropertiesPcapFile())
		if err != nil {
			return
		}

		pcapDescForProtoDection = newPcapFileDesc(getPropertiesPcapFile())
		if err != nil {
			pcapDescForSniff.Close()
			pcapDescForSniff = nil
			return
		}
	}

	datalinkTypeForSniff = pcapDescForSniff.Datalink()
	datalinkTypeForProtoDetection = pcapDescForProtoDection.Datalink()

	if datalinkTypeForSniff < 0 || datalinkTypeForProtoDetection < 0 {
		pcapDescForSniff.Close()
		pcapDescForSniff = nil
		pcapDescForProtoDection.Close()
		pcapDescForProtoDection = nil;
		return errors.New("Invalid datalink type")
	}

	return nil;
}

func destroyNetDev() {
	if pcapDescForSniff != nil {
		pcapDescForSniff.Close()
		pcapDescForSniff = nil
	}

	if pcapDescForProtoDection != nil {
		pcapDescForProtoDection.Close()
		pcapDescForProtoDection = nil
	}
}
