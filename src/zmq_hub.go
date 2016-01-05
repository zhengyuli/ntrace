package main

import (
    "fmt"
    "runtime"
    zmq "github.com/alecthomas/gozmq"
)

const (
    IP_PACKET_EXCHANGE_CHANNEL = "inproc://ipPacketExchangeChannel"
    ICMP_PACKET_EXCHANGE_CHANNEL = "inproc://icmpPacketExchangeChannel"
    TCP_PACKET_EXCHANGE_CHANNEL = "inproc://tcpPacketExchangeChannel"
    ANALYSIS_RECORD_EXCHANGE_CHANNEL = "inproc://analysisRecordExchangeChannel"
)

type zmqHub struct {
    // Zmq context
    zmqCtxt *zmq.Context

    /* Analysis record recv sock */
    analysisRecordRecvSock *zmq.Socket

    /* Topology entry send sock */
    topologyEntrySendSock *zmq.Socket

    /* Application service send sock */
    appServiceSendSock *zmq.Socket

    /* Ip packet recv sock */
    ipPktRecvSock *zmq.Socket
    /* Ip packet send sock */
    ipPktSendSock *zmq.Socket

    /* Icmp packet recv sock */
    icmpPktRecvSock *zmq.Socket
    /* Icmp packet send sock */
    icmpPktSendSock *zmq.Socket
    /* Icmp error send sock */
    icmpErrorSendSock *zmq.Socket

    /* Tcp process threads number */
    tcpProcessThreadsNum int
    /* Tcp packet dispatch recv socks */
    tcpPktRecvSocks []*zmq.Socket
    /* Tcp packet dispatch send socks */
    tcpPktSendSocks []*zmq.Socket
    /* Tcp breakdown send socks */
    tcpBreakdownSendSocks []*zmq.Socket
}

var globalZmqHub zmqHub

func initZmqHub() (err error) {
    // Create zmq context
    globalZmqHub.zmqCtxt, err = zmq.NewContext()
    if err != nil {
        goto err
    }

    // Set zmq context io threads
    err = globalZmqHub.zmqCtxt.SetIOThreads(3)
    if err != nil {
        goto err
    }

    // Create analysis record recv sock
    globalZmqHub.analysisRecordRecvSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PULL)
    if err != nil {
        goto err
    }
    err = globalZmqHub.analysisRecordRecvSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.analysisRecordRecvSock.SetRcvHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.analysisRecordRecvSock.Bind(ANALYSIS_RECORD_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Create topologyEntrySendSock
    globalZmqHub.topologyEntrySendSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PUSH)
    if err != nil {
        goto err
    }
    err = globalZmqHub.topologyEntrySendSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.topologyEntrySendSock.SetSndHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.topologyEntrySendSock.Connect(ANALYSIS_RECORD_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Create appServiceSendSock
    globalZmqHub.appServiceSendSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PUSH)
    if err != nil {
        goto err
    }
    err = globalZmqHub.appServiceSendSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.appServiceSendSock.SetSndHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.appServiceSendSock.Connect(ANALYSIS_RECORD_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Create ipPktRecvSock
    globalZmqHub.ipPktRecvSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PULL)
    if err != nil {
        goto err
    }
    err = globalZmqHub.ipPktRecvSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.ipPktRecvSock.SetRcvHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.ipPktRecvSock.Bind(IP_PACKET_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Create ipPktSendSock
    globalZmqHub.ipPktSendSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PUSH)
    if err != nil {
        goto err
    }
    err = globalZmqHub.ipPktSendSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.ipPktSendSock.SetSndHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.ipPktSendSock.Connect(IP_PACKET_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Create icmpPktRecvSock
    globalZmqHub.icmpPktRecvSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PULL)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpPktRecvSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpPktRecvSock.SetRcvHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpPktRecvSock.Bind(ICMP_PACKET_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Create icmpPktSendSock
    globalZmqHub.icmpPktSendSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PUSH)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpPktSendSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpPktSendSock.SetSndHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpPktSendSock.Connect(ICMP_PACKET_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Create icmpErrorSendSock
    globalZmqHub.icmpErrorSendSock, err = globalZmqHub.zmqCtxt.NewSocket(zmq.PUSH)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpErrorSendSock.SetLinger(0)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpErrorSendSock.SetSndHWM(500000)
    if err != nil {
        goto err
    }
    err = globalZmqHub.icmpErrorSendSock.Connect(ANALYSIS_RECORD_EXCHANGE_CHANNEL)
    if err != nil {
        goto err
    }

    // Get tcp process threads number
    globalZmqHub.tcpProcessThreadsNum = runtime.NumCPU()

    globalZmqHub.tcpPktRecvSocks = make([]*zmq.Socket, globalZmqHub.tcpProcessThreadsNum)
	globalZmqHub.tcpPktSendSocks = make([]*zmq.Socket, globalZmqHub.tcpProcessThreadsNum)
    globalZmqHub.tcpBreakdownSendSocks = make([]*zmq.Socket, globalZmqHub.tcpProcessThreadsNum)
    for i := 0; i < globalZmqHub.tcpProcessThreadsNum; i++ {
		// Create tcpPktRecvSocks
        globalZmqHub.tcpPktRecvSocks[i], err = globalZmqHub.zmqCtxt.NewSocket(zmq.PULL)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpPktRecvSocks[i].SetLinger(0)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpPktRecvSocks[i].SetRcvHWM(500000)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpPktRecvSocks[i].Bind(
            fmt.Sprintf("%s:%d", TCP_PACKET_EXCHANGE_CHANNEL, i))
        if err != nil {
            goto err
        }

		// Create tcpPktSendSocks
        globalZmqHub.tcpPktSendSocks[i], err = globalZmqHub.zmqCtxt.NewSocket(zmq.PUSH)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpPktSendSocks[i].SetLinger(0)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpPktSendSocks[i].SetSndHWM(500000)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpPktSendSocks[i].Connect(
            fmt.Sprintf("%s:%d", TCP_PACKET_EXCHANGE_CHANNEL, i))
        if err != nil {
            goto err
        }

		// Create tcpBreakdownSendSocks
        globalZmqHub.tcpBreakdownSendSocks[i], err = globalZmqHub.zmqCtxt.NewSocket(zmq.PUSH)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpBreakdownSendSocks[i].SetLinger(0)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpBreakdownSendSocks[i].SetSndHWM(500000)
        if err != nil {
            goto err
        }
        err = globalZmqHub.tcpBreakdownSendSocks[i].Connect(ANALYSIS_RECORD_EXCHANGE_CHANNEL)
        if err != nil {
            goto err
        }
    }
    return nil

err:
    for i := 0; i < globalZmqHub.tcpProcessThreadsNum; i++ {
        if globalZmqHub.tcpBreakdownSendSocks[i] != nil {
            globalZmqHub.tcpBreakdownSendSocks[i].Close()
        }

        if globalZmqHub.tcpPktRecvSocks[i] != nil {
            globalZmqHub.tcpPktRecvSocks[i].Close()
        }

        if globalZmqHub.tcpPktSendSocks[i] != nil {
            globalZmqHub.tcpPktSendSocks[i].Close()
        }
    }

    if globalZmqHub.icmpErrorSendSock != nil {
        globalZmqHub.icmpErrorSendSock.Close()
    }

    if globalZmqHub.icmpPktSendSock != nil {
        globalZmqHub.icmpPktSendSock.Close()
    }

    if globalZmqHub.icmpPktRecvSock != nil {
        globalZmqHub.icmpPktRecvSock.Close()
    }

    if globalZmqHub.ipPktSendSock != nil {
        globalZmqHub.ipPktSendSock.Close()
    }

    if globalZmqHub.ipPktRecvSock != nil {
        globalZmqHub.ipPktRecvSock.Close()
    }

    if globalZmqHub.appServiceSendSock != nil {
        globalZmqHub.appServiceSendSock.Close()
    }

    if globalZmqHub.topologyEntrySendSock != nil {
        globalZmqHub.topologyEntrySendSock.Close()
    }

    if globalZmqHub.analysisRecordRecvSock != nil {
        globalZmqHub.analysisRecordRecvSock.Close()
    }

    globalZmqHub.zmqCtxt.Close()
	return err
}

func destroyZmqHub() {
	for i := 0; i < globalZmqHub.tcpProcessThreadsNum; i++ {
		globalZmqHub.tcpBreakdownSendSocks[i].Close()

		globalZmqHub.tcpPktSendSocks[i].Close()

		globalZmqHub.tcpPktRecvSocks[i].Close()
    }

	globalZmqHub.icmpErrorSendSock.Close()

	globalZmqHub.icmpPktSendSock.Close()

	globalZmqHub.icmpPktRecvSock.Close()

	globalZmqHub.ipPktSendSock.Close()

	globalZmqHub.ipPktRecvSock.Close()

	globalZmqHub.appServiceSendSock.Close()

	globalZmqHub.topologyEntrySendSock.Close()

	globalZmqHub.analysisRecordRecvSock.Close()

    globalZmqHub.zmqCtxt.Close()
}
