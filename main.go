package main

import (
	"fmt"
	"goconf/conf"
	"proto"
	"proto/raw"
	"sniffer"
	"time"
)

type properties struct {
	// Management service port
	managementServicePort uint16

	// Network device to sniff
	netDev string

	// File output settings
	outputFile string

	// Splunk output settings
	// Splunk index for analysis record
	splunkIndex string
	// Splunk source for analysis record
	splunkSource string
	// Splunk sourcetype for analysis record
	splunkSourcetype string
	// Splunk auth token for http event collector
	splunkAuthToken string
	// Splunk url for http event collector
	splunkUrl string

	// Log settings
	// Log dir
	logDir string
	// Log file
	logFile string
	// Log level
	logLevel int
}

var globalProperties properties

func initProperties(configFile string) (err error) {
	c, err := conf.ReadConfigFile(configFile)
	if err != nil {
		return
	}

	// Get management_service port
	port, err := c.GetInt("management_service", "port")
	if err != nil {
		return
	}
	globalProperties.managementServicePort = uint16(port)

	// Get network device
	globalProperties.netDev, err = c.GetString("input", "netdev")
	if err != nil {
		return
	}

	// Get file_output settings
	if c.HasSection("file_output") {
		// Get file_output file
		globalProperties.outputFile, err = c.GetString("file_output", "file")
		if err != nil {
			return
		}
	}

	// Get splunk_output settings
	if c.HasSection("splunk_output") {
		// Get splunk_output index
		globalProperties.splunkIndex, err = c.GetString("splunk_output", "index")
		if err != nil {
			return
		}

		// Get splunk_utput source
		globalProperties.splunkSource, err = c.GetString("splunk_output", "source")
		if err != nil {
			return
		}

		// Get splunk_output sourcetype
		globalProperties.splunkSourcetype, err = c.GetString("splunk_output", "sourcetype")
		if err != nil {
			return
		}

		// Get splunk output auth_token
		globalProperties.splunkAuthToken, err = c.GetString("splunk_output", "auth_token")
		if err != nil {
			return
		}

		// Get splunk output url
		globalProperties.splunkUrl, err = c.GetString("splunk_output", "url")
		if err != nil {
			return
		}
	}

	// Get log dir
	globalProperties.logDir, err = c.GetString("log", "dir")
	if err != nil {
		return
	}

	// Get log file
	globalProperties.logFile, err = c.GetString("log", "file")
	if err != nil {
		return
	}

	// Get log level
	globalProperties.logLevel, err = c.GetInt("log", "level")
	if err != nil {
		return
	}

	return
}

func displayPropertiesDetail() {
	fmt.Printf("Startup with properties:{\n")
	fmt.Printf("    managementServicePort: %v\n", globalProperties.managementServicePort)
	fmt.Printf("    netDev: %v\n", globalProperties.netDev)
	fmt.Printf("    outputFile: %v\n", globalProperties.outputFile)
	fmt.Printf("    splunkIndex: %v\n", globalProperties.splunkIndex)
	fmt.Printf("    splunkSource: %v\n", globalProperties.splunkSource)
	fmt.Printf("    splunkSourcetype: %v\n", globalProperties.splunkSourcetype)
	fmt.Printf("    splunkAuthToken: %v\n", globalProperties.splunkAuthToken)
	fmt.Printf("    splunkUrl: %v\n", globalProperties.splunkUrl)
	fmt.Printf("    logDir: %v\n", globalProperties.logDir)
	fmt.Printf("    logFileName: %v\n", globalProperties.logFile)
	fmt.Printf("    logLevel: %v\n}\n", globalProperties.logLevel)
}

var rawPktCaptureSize uint64
var rawPktCaptureStartTime time.Time

func displayRawCaptureStatisticInfo() {
	rawPktCaptureEndTime := time.Now()
	runDuration := rawPktCaptureEndTime.Sub(rawPktCaptureStartTime)

	fmt.Printf("\n"+
		"==Capture raw packets complete==\n"+
		"--size: %f KB\n"+
		"--interval: %f ms\n"+
		"--rate: %f Mb/s\n\n",
		float64(rawPktCaptureSize/1024),
		float64(runDuration/time.Millisecond),
		float64((rawPktCaptureSize/(128*1024))/uint64(runDuration/time.Second+1)))
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
		panic(err)
	}
	datalink, err := handle.Datalink()
	if err != nil {
		panic(err)
	}

	rawPktCaptureStartTime = time.Now()
	for {
		rawPkt, err := handle.NextPacket()
		if err != nil {
			panic(err)
		}

		if rawPkt != nil {
			// Filter out incomplete raw packet
			if rawPkt.CapLen != rawPkt.Len {
				continue
			}

			rawPktCaptureSize += uint64(rawPkt.CapLen)

			// Get ip packet
			ipPktOffset, err := raw.GetIpPktOffset(rawPkt.Data, datalink)
			if err != nil {
				fmt.Println(err)
				continue
			}

			var protoCache proto.ProtoCache
			protoCache.Time = rawPkt.Time
			protoCache.Datalink = datalink
			if datalink == raw.LINKTYPE_ETHERNET {
				protoCache.SrcMac = rawPkt.Data[0:6]
				protoCache.DstMac = rawPkt.Data[6:12]
			}
			protoCache.Data = rawPkt.Data[ipPktOffset:]
			fmt.Printf("packet cache:%#v\n", protoCache)
		}
	}
}

func main() {
	displayNtraceStartupInfo()

	err := initProperties("./ntrace.conf")
	if err != nil {
		fmt.Printf("Init properties error: %v.\n", err)
		return
	}

	err = initZmqHub()
	if err != nil {
		fmt.Printf("Init zmq hub error: %v.\n", err)
		return
	}

	rawCaptureService()

	destroyZmqHub()
}
