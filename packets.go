package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Layers we want to parse. This approach speeds up packet processing by reusing the same
// layer memory repeatedly.  Make sure to set numLayers to the number of layers you expect
// since the memory is preallocated based on how many layers are expected.
const numLayers = 4

var (
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	ipv6ext layers.IPv6ExtensionSkipper
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

// TCP flags as constants
const (
	FIN byte = 0x01
	SYN byte = 0x02
	RST byte = 0x04
	PSH byte = 0x08
	ACK byte = 0x10
	URG byte = 0x20
)

// PrintPacketStats prints packet stats
func PrintPacketStats() {
	fmt.Println("Total packets:", totalPackets)
	fmt.Println("Packets decoded:", numDecoded)
}

// HandleDecodedLayers contains logic for processing packet layers.  It is run as a goroutine
// depends on two channels. layerChan receives layers, and done sends a signal that processing
// is finished where there are no more layers in layerChan.
func HandleDecodedLayers(layerChan <-chan []gopacket.LayerType, done chan<- bool) {
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

// ProcessPackets reads packet from a source until either an EOF (PCAP files) or a termination
// signal (live network device).
func ProcessPackets(handle *pcap.Handle) {
	// Set up our channels for sending decoded layers to handleDecodedLayers (a worker goroutine).
	// Two channels are used: layerChan is a channel for sending decoded packets to the worker, and
	// doneChan is used by the worker to indicate it has finished handling all decoded layers in
	// layerChan.  signalReceived is used by the signalHandler to short-circuit the packet capture
	// loop when a SIGTERM or ^C is received.  The allows us to shut down gracefully by closing
	// layerChan, letting the worker finish, and wrapping up any loose ends.
	layerChan := make(chan []gopacket.LayerType, 256)
	doneChan := make(chan bool)
	signalReceived := false
	go HandleDecodedLayers(layerChan, doneChan)

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
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &ipv6ext,
		&tcp, &udp, &icmp, &icmp6, &payload)
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
				// We have an error reading a packet. Skip it.
				continue
			}

			// We have a valid packet, so parse it based on our layer parser.
			totalPackets++
			if err = parser.DecodeLayers(data, &decoded); err != nil {
				// We can't parse this packet based on our layers. Skip it.
				continue
			}

			if parser.Truncated {
				// We have a truncated packet. Skip it.
				continue
			}
			layerChan <- decoded
		}
	}

	// Close the channels and shut things down.
	close(layerChan)
	<-doneChan
	PrintPacketStats()
}
