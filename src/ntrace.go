package main

import (
	"fmt"
)

func main() {
	displayNtraceStartupInfo()

	err := initProperties("./ntrace.conf")
	if err != nil {
		fmt.Printf("Init properties error: %v.\n", err)
		return
	}

	err = initNetDev()
	if err != nil {
		fmt.Printf("Init network device error: %v.\n", err)
		return
	}

	err = initZmqHub()
	if err != nil {
		fmt.Printf("Init zmq hub error: %v.\n", err)
		return
	}

	destroyZmqHub()
	destroyNetDev()
}
