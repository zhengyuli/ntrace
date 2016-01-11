package main

import (
    "fmt"
    "time"
	"sniffer"
    "proto"
    "proto/raw"
)

var rawPktCaptureSize uint64
var rawPktCaptureStartTime time.Time

func displayRawCaptureStatisticInfo() {
    rawPktCaptureEndTime := time.Now()
    runDuration := rawPktCaptureEndTime.Sub(rawPktCaptureStartTime)

    fmt.Printf ("\n" +
        "==Capture raw packets complete==\n" +
        "--size: %f KB\n" +
        "--interval: %f ms\n" +
        "--rate: %f Mb/s\n\n",
        float64(rawPktCaptureSize / 1024),
        float64(runDuration / time.Millisecond),
        float64((rawPktCaptureSize / (128 * 1024)) / uint64(runDuration / time.Second + 1)))
}

func rawCaptureService() {
	defer func() {
		err := recover()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}

		fmt.Printf("Raw capture service will exit\n")
		displayRawCaptureStatisticInfo()
	}()

	handle, err := sniffer.NewSniffer(globalProperties.netDev)
	if err != nil {
		panic(fmt.Sprintf("Open sniffer on: %s error", globalProperties.netDev))
	}
	datalink, datalinkName := handle.Datalink()

    rawPktCaptureStartTime = time.Now()
    for {
        rawPkt, err := handle.NextEx()
        if err != nil {
			panic(err)
        }

        if rawPkt != nil {
            // Filter out incomplete raw packet
            if rawPkt.CapLen != rawPkt.Len {
                continue
            }

            rawPktCaptureSize += uint64(rawPkt.CapLen);

            // Get ip packet
            ipPktOffset, err := raw.GetIpPktOffset(rawPkt.Data, datalink)
            if err != nil {
                fmt.Println(err)
                continue
            }

            var pktCache proto.PacketCache
            pktCache.Time = rawPkt.Time
            pktCache.Datalink = datalinkName
            if datalink == raw.LINKTYPE_ETHERNET {
                pktCache.SrcMac = rawPkt.Data[0:6]
                pktCache.DstMac = rawPkt.Data[6:12]
            }
			pktCache.Data = rawPkt.Data[ipPktOffset:]
            fmt.Printf("packet cache:%#v\n", pktCache)
        }
    }
}
