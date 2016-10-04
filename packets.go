// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Layers we want to parse. This approach speeds up packet processing by reusing the same
// layer memory repeatedly.  Make sure to set numLayers to the number of layers you expect
// since the memory is preallocated based on how many layers are expected.
const numLayers = 4

var (
	eth     layers.Ethernet             // layer 1
	dot1q   layers.Dot1Q                // layer 1
	ip4     layers.IPv4                 // layer 2
	ip6     layers.IPv6                 // layer 2
	ipv6ext layers.IPv6ExtensionSkipper // layer 2
	tcp     layers.TCP                  // layer 3
	udp     layers.UDP                  // layer 3
	icmp    layers.ICMPv4               // layer 3
	icmp6   layers.ICMPv6               // layer 3
	payload gopacket.Payload            // layer 4
)

// MetaPacket ...
type MetaPacket struct {
	id            uint64            // Unique packet identifier
	ts            time.Time         // Capture timestamp in Unix nanoseconds
	sip           [16]byte          // Source IP address for IPv4 or IPv6
	dip           [16]byte          // Dest IP address for IPv4 or IPv6
	ipver         int               // 4 if IPv4, 6 if IPv6
	sport         uint16            // Source port for TCP and UDP, typecode for ICMP
	dport         uint16            // Dest port for TCP and UDP
	protocol      layers.IPProtocol // TCP, UDP, ICMP, ICMPv6
	payloadLength uint16            // Number of bytes in application payload
	packetLength  uint16            // Number of bytes in the packet (CaptureInfo.Length)
	tcpFlags      byte              // TCP flags if packet is TCP
}

// Summary statistics variables
var (
	numBytes     uint64
	numDecoded   uint64
	numErrors    uint64
	numTruncated uint64
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

var zeroByteArray = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// PrintMetaPacket pretty-prints a MetaPacket type to standard output.
func PrintMetaPacket(mp MetaPacket) {
	fmt.Printf("{id: %d, ts: %d, ip: %v", mp.id, mp.ts.UnixNano(), mp.ipver)
	if mp.ipver == 4 {
		fmt.Printf(", sip: %s, dip: %s, proto: %s", net.IP(mp.sip[:4]).String(),
			net.IP(mp.dip[:4]).String(), mp.protocol.String())
	} else {
		fmt.Printf(", sip: %s, dip: %s, proto: %s", net.IP(mp.sip[:]).String(),
			net.IP(mp.dip[:]).String(), mp.protocol.String())
	}
	switch mp.protocol {
	case layers.IPProtocolTCP:
		fallthrough
	case layers.IPProtocolUDP:
		fmt.Printf(", sport: %d, dport: %d", mp.sport, mp.dport)
	case layers.IPProtocolICMPv4:
		fmt.Printf(", typecode: %v", layers.ICMPv4TypeCode(mp.sport).String())
	case layers.IPProtocolICMPv6:
		fmt.Printf(", typecode: %v", layers.ICMPv6TypeCode(mp.sport).String())
	}
	fmt.Printf(", payload: %v", mp.payloadLength)
	fmt.Println("}")
}

// ProcessPackets reads packet from a source until either an EOF (PCAP files) or a termination
// signal (live network device).
func ProcessPackets(handle *pcap.Handle) {
	// Set up our channels for sending decoded layers to handleDecodedLayers (a worker goroutine).
	// Two channels are used: layerChan is a channel for sending decoded packets to the worker, and
	// doneChan is used by the worker to indicate it has finished handling all decoded
	// layers in layerChan.  The allows us to shut down gracefully by closing layerChan, letting the
	// worker finish, and wrapping up any loose ends.
	metaPacketChan := make(chan MetaPacket, 256)
	doneChan := make(chan bool, 1) // Channel
	go func() {
		for p := range metaPacketChan {
			if verbose {
				PrintMetaPacket(p)
			}
		}
		doneChan <- true
	}()

	// Set up a goroutine to handle shutdown signals on signalChan. This lets the program gracefully
	// shut down on ^C or SIGTERM.
	shutdownChan := make(chan bool, 1) // Channel that alerts on SIGTERM or SIGINT
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("Received ^C. Gracefully shutting down.")
		shutdownChan <- true
	}()

	// This is the main packet processing loop. It reads packets from the source, decodes them
	// into layers, and passes them to the worker via the layerChan channel.
	var mp MetaPacket
	decoded := make([]gopacket.LayerType, 0, numLayers)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6,
		&ipv6ext, &tcp, &udp, &icmp, &icmp6, &payload)

Loop:
	for {
		select {
		case <-shutdownChan:
			break Loop
		default:
			data, ci, err := handle.ZeroCopyReadPacketData()
			if err == io.EOF {
				// All packets from a PCAP file have been read (not applicable to a live device).
				break Loop
			} else if err != nil {
				// We have an error reading a packet. Skip it.
				continue Loop
			}

			// We have a valid packet, so parse it based on our layer parser.
			totalPackets++
			if err = parser.DecodeLayers(data, &decoded); err != nil {
				// This error means we have a packet that does not conform to the layers we expected
				// to receive.  That could mean we have something interesting to investigate.
				// TODO: We need to provide an analytic or forensics capability for this case. Bytes
				// in `data` describe the packet and can be dumped to a file for further analysis.
				numErrors++
				continue Loop
			}
			numDecoded++
			numBytes += uint64(len(data))

			if parser.Truncated {
				// We have a truncated packet. Skip it for now.
				// TODO: How are truncated packets handled?
				numTruncated++
				continue Loop
			}

			// We are ready to send a Packet to packetChan, but we need to copy values, not copy
			// references to values. We deep copy the slices we are interested in preserving across
			// the channel.
			// NOTE: This may be a profiling and optimization target.
			mp.id = numDecoded
			mp.ts = ci.Timestamp
			mp.packetLength = uint16(len(data))
			for _, typ := range decoded {
				switch typ {
				case layers.LayerTypeIPv4:
					mp.sip = zeroByteArray
					mp.dip = zeroByteArray
					copy(mp.sip[:], ip4.SrcIP)
					copy(mp.dip[:], ip4.DstIP)
					mp.ipver = 4
				case layers.LayerTypeIPv6:
					mp.sip = zeroByteArray
					mp.dip = zeroByteArray
					copy(mp.sip[:], ip6.SrcIP)
					copy(mp.dip[:], ip6.DstIP)
					mp.ipver = 6
				case layers.LayerTypeTCP:
					mp.sport = uint16(tcp.SrcPort)
					mp.dport = uint16(tcp.DstPort)
					mp.protocol = layers.IPProtocolTCP
					mp.tcpFlags = 0x00
					if tcp.FIN {
						mp.tcpFlags |= FIN
					}
					if tcp.SYN {
						mp.tcpFlags |= SYN
					}
					if tcp.RST {
						mp.tcpFlags |= RST
					}
					if tcp.PSH {
						mp.tcpFlags |= PSH
					}
					if tcp.ACK {
						mp.tcpFlags |= ACK
					}
					if tcp.URG {
						mp.tcpFlags |= URG
					}
				case layers.LayerTypeUDP:
					mp.sport = uint16(udp.SrcPort)
					mp.dport = uint16(udp.DstPort)
					mp.protocol = layers.IPProtocolUDP
				case layers.LayerTypeICMPv4:
					mp.sport = uint16(icmp.TypeCode)
					mp.dport = 0
					mp.protocol = layers.IPProtocolICMPv4
				case layers.LayerTypeICMPv6:
					mp.sport = uint16(icmp6.TypeCode)
					mp.dport = 0
					mp.protocol = layers.IPProtocolICMPv6
				case gopacket.LayerTypePayload:
					mp.payloadLength = uint16(len(payload))
				}
			}
			metaPacketChan <- mp
		}
	}
	close(metaPacketChan)
	<-doneChan
	if verbose {
		fmt.Printf("Processed %v packets (%v bytes) with %v decoded, %v errors, and %v truncated.\n",
			totalPackets, numBytes, numDecoded, numErrors, numTruncated)
	}
}
