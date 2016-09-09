// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.
// This source code is covered by the license found in the LICENSE file.
//
// Ing is a packet processor and metadata collector based on gopacket.  It reads packets from a
// PCAP file or a live network device.

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Version values passed in by the linker with go build, go run, go install are called.
var (
	version   string
	buildTime string
	gitHash   string
)

// Layers we want to parse. This approach speeds up packet processing by reusing the same
// layer memory repeatedly.  Make sure to set numLayers to the number of layers you expect
// since the memory is preallocated based on how many layers are expected.
const numLayers = 4

var (
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp    layers.ICMPv4
	icmp6   layers.ICMPv6
	payload gopacket.Payload
)

// Summary statistics variables
var (
	numDecoded   uint64
	totalPackets uint64
)

// printPacketStats prints packet stats
func printPacketStats() {
	fmt.Println("Total packets:", totalPackets)
	fmt.Println("Packets decoded:", numDecoded)
}

// handleDecodedLayers contains logic for processing packet layers.  It is run as a goroutine
// depends on two channels. layerChan receives layers, and done sends a signal that processing
// is finished where there are no more layers in layerChan.
// NOTE: This should go into a separate file.
func handleDecodedLayers(layerChan <-chan []gopacket.LayerType, done chan<- bool) {
	for {
		decoded, more := <-layerChan
		if more {
			numDecoded++
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeEthernet:
				default:
				}
			}
		} else {
			done <- true
			return
		}
	}
}

// processPackets reads packet from a source until either an EOF (PCAP files) or a termination
// signal (live network device).
func processPackets(handle *pcap.Handle) {
	// Set up our channels for sending decoded layers to handleDecodedLayers (a worker goroutine).
	// Two channels are used: layerChan is a channel for sending decoded packets to the worker, and
	// doneChan is used by the worker to indicate it has finished handling all decoded layers in
	// layerChan.  signalReceived is used by the signalHandler to short-circuit the packet capture
	// loop when a SIGTERM or ^C is received.  The allows us to shut down gracefully by closing
	// layerChan, letting the worker finish, and wrapping up any loose ends.
	layerChan := make(chan []gopacket.LayerType, 256)
	doneChan := make(chan bool)
	signalReceived := false
	go handleDecodedLayers(layerChan, doneChan)

	// Gracefully shut down on ^C or SIGTERM. Make sure to close layerChan or the worker won't
	// know to stop.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("Received ^C. Gracefully shutting down.")
		signalReceived = true
		handle.Close() // Call Close() because deferred functions are called on Exit().
		os.Exit(0)
	}()

	// This is the main packet processing loop. It reads packets from the source, decodes them
	// into layers, and passes them to the worker via the layerChan channel.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &icmp, &icmp6, &payload)
	decoded := make([]gopacket.LayerType, numLayers)
	for {
		if signalReceived {
			break
		} else {
			data, _, err := handle.ZeroCopyReadPacketData()
			if err == io.EOF {
				// All packets from a PCAP file have been read (not applicable to a live device).
				break
			} else if err != nil {
				// We have an error reading a packet. Skip it for now.
				continue
			}

			// We have a valid packet, so parse it based on our layer parser.
			totalPackets++
			if err = parser.DecodeLayers(data, &decoded); err != nil {
				// We can't parse this packet based on our layers.
				continue
			}

			if parser.Truncated {
				// We have a truncated packet.
				continue
			}
			layerChan <- decoded
		}
	}

	// Close the channels and shut things down.
	close(layerChan)
	<-doneChan
	printPacketStats()
}

func main() {
	var packetHandle *pcap.Handle
	var err error

	bpf := flag.String("bpf", "", "Berkeley Packet Filter expression")
	isDevice := flag.Bool("device", false, "INPUT is a live network device")
	snaplen := flag.Int("snaplen", 65536, "Read snaplen bytes from each packet")
	showVersion := flag.Bool("version", false, "Show version information and exit")

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
		packetHandle, err = pcap.OpenLive(args[0], int32(*snaplen), true, pcap.BlockForever)
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

	processPackets(packetHandle)
}
