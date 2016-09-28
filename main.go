// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.
// This source code is covered by the license found in the LICENSE file.
//
// Ing is a packet processor and metadata collector based on gopacket.  It reads packets from a
// PCAP file or a live network device.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket/pcap"
)

// Version values passed in by the linker with go build, go run, go install are called.
var (
	version   string
	buildTime string
	gitHash   string
)

func main() {
	var packetHandle *pcap.Handle
	var err error

	// Since these flags are local to this function, i.e. setting up a PCAP handle, we don't need
	// them as global configuration variables.
	bpf := flag.String("bpf", "", "Berkeley Packet Filter expression")
	isDevice := flag.Bool("device", false, "INPUT is a live network device")
	snaplen := flag.Int("snaplen", 65536, "Read snaplen bytes from each packet")
	showVersion := flag.Bool("version", false, "Show version information and exit")

	// These are global configuration variables, so we need to call XxxVar().
	flag.BoolVar(&DebugPrintPackets, "debug-print-packets", false, "Print packets in short form")
	flag.BoolVar(&DebugPrintFlows, "debug-print-flows", false, "Print flows in short form")
	flag.UintVar(&ActiveTimeout, "active-timeout", 1800, "Active flow timeout in seconds")
	flag.UintVar(&IdleTimeout, "idle-timeout", 63, "Inactive flow timout in seconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] INPUT\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "INPUT: Packet source either as a PCAP file or a network device.\n")
		fmt.Fprintf(os.Stderr, "       If the latter, use the `--device` switch.\n\n")
		fmt.Fprintf(os.Stderr, "OPTIONS:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()

	if *showVersion {
		fmt.Println(os.Args[0], "version", version)
		fmt.Println("Build timestamp: ", buildTime)
		fmt.Println("Git commit: ", gitHash)
		os.Exit(0)
	}

	if len(args) < 1 {
		fmt.Println("Please provide a packet source.")
		os.Exit(1)
	}

	if *isDevice {
		packetHandle, err = pcap.OpenLive(args[0], int32(*snaplen), true, PcapTimeout)
	} else {
		packetHandle, err = pcap.OpenOffline(args[0])
	}
	defer packetHandle.Close()

	if err != nil {
		log.Fatalln("PCAP handle error:", err)
	}

	if len(*bpf) > 0 {
		if err := packetHandle.SetBPFFilter(*bpf); err != nil {
			log.Fatalln("BPF error:", err)
		}
	}

	ProcessPackets(packetHandle)
}
