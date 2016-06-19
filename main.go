package main

import (
	"bitbucket.org/zhengyuli/ntrace/decode"
	"bitbucket.org/zhengyuli/ntrace/layers"
	"bitbucket.org/zhengyuli/ntrace/sniffer"
	"bitbucket.org/zhengyuli/ntrace/sniffer/driver"
	log "github.com/Sirupsen/logrus"
	"os"
	"path"
	// "time"
)

var netDev = "en0"

// SetupDefaultLogger config default logger settings with specified
// log file name, default log formatter and default log level.
func setupDefaultLogger(logDir string, logFile string, logLevel log.Level) (*os.File, error) {
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

func rawCaptureService() {
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("RawCaptureService run with error: %s", err)
		}

		log.Info("Raw capture service exit... .. .")
	}()

	handle, err := sniffer.New(netDev)
	if err != nil {
		panic(err)
	}

	pkt := new(driver.Packet)
	for {
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

			var layerType layers.LayerType
			layerType = handle.DatalinkType()
			payload := pkt.Data
			for {
				if layerType == layers.NullLayerType {
					break
				}

				decoder := decode.New(layerType)
				if decoder == decode.NullDecoder {
					log.Errorf("No proper decoder for %s.", layerType)
					break
				}
				if err = decoder.Decode(payload); err != nil {
					log.Errorf("Decode %s error: %s", layerType, err)
					break
				}
				log.Infof("%s", decoder)

				layerType = decoder.NextLayerType()
				payload = decoder.LayerPayload()
			}
		}
	}
}

func main() {
	out, err := setupDefaultLogger("/var/log", "ntrace", log.DebugLevel)
	if err != nil {
		log.Fatalf("Setup default logger with error: %s.", err)
	}
	defer out.Close()

	rawCaptureService()
}
