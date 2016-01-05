package main

import (
	"fmt"
	"errors"
	"gconf/conf"
)

type properties struct {
	// Management service port
	managementServicePort uint16

	// Network device to sniff
	netDev string

	// Splunk output settings
	// Splunk index for analysis record
	splunkIndex string
	// Splunk source for analysis record
	splunkSource string
	// Splunk sourcetype for analysis record
	splunkSourcetype
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
};

var globalProperties properties

func initProperties (configFile string) (err error) {
	c, err = conf.ReadConfigFile(configFile)
	if err != nil {
		return
	}

    // Get managementService port
	globalProperties.managementServicePort, err = c.GetInt("managementService", "port")
	if err != nil {
		return
	}

    // Get liveInput interface
	globalProperties.netDev, err = c.GetString("input", "netDev")
	if err != nil {
		return
	}

    // Get fileOutput outputFile
	globalProperties.outputFile, err = c.GetString("fileOutput", "outputFile")
	if err != nil {
		return
	}

    // Get splunkOutput index
	globalProperties.splunkIndex, err = c.GetString("splunkOutput", "index")
	if err != nil {
		return
	}

    // Get splunkOutput source
	globalProperties.splunkSource, err = c.GetString("splunkOutput", "source")
	if err != nil {
		return
	}

    // Get splunkOutput sourcetype
	globalProperties.splunkSourcetype, err = c.GetString("splunkOutput", "sourcetype")
	if err != nil {
		return
	}

    // Get splunkOutput authToken
	globalProperties.splunkAuthToken, err = c.GetString("splunkOutput", "authToken")
	if err != nil {
		return
	}

    // Get splunkOutput url
	globalProperties.splunkUrl, err = c.GetString("splunkOutput", "url")
	if err != nil {
		return
	}

    // Get log logDir
	globalProperties.logDir, err = c.GetString("log", "logDir")
	if err != nil {
		return
	}

    // Get log logFile
	globalProperties.logFile, err = c.GetString("log", "logFile")
	if err != nil {
		return
	}


    // Get log logLevel
	globalProperties.logLevel, err = c.GetString("log", "logLevel")
	if err != nil {
		return
	}

	return nil
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

func main() {
	initProperties("./ntrace.conf")
	displayPropertiesDetail()
}
