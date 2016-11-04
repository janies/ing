// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"fmt"
	"io"
	"log"
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
	eth     layers.Ethernet             // gopacket layer 1
	dot1q   layers.Dot1Q                // gopacket layer 1
	ip4     layers.IPv4                 // gopacket layer 2
	ip6     layers.IPv6                 // gopacket layer 2
	ipv6ext layers.IPv6ExtensionSkipper // gopacket layer 2
	icmp    layers.ICMPv4               // gopacket layer 2
	icmp6   layers.ICMPv6               // gopacket layer 2
	tcp     layers.TCP                  // gopacket layer 3
	udp     layers.UDP                  // gopacket layer 3
	dns     layers.DNS                  //gopacket layer 4
	payload gopacket.Payload            // gopacket layer 4
)

// TCP flags as constants
const (
	FIN byte = 0x01
	SYN byte = 0x02
	RST byte = 0x04
	PSH byte = 0x08
	ACK byte = 0x10
	URG byte = 0x20
	ECE byte = 0x40
	CWR byte = 0x80
)

var zeroByteArray = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// MetaPacket captures everything about a packet that we are about in downstream computations. It
// is a flat data structure with minimal composition.
type MetaPacket struct {
	id            uint64            // Unique packet identifier
	timestamp     time.Time         // Capture timestamp in Unix nanoseconds
	sip           IPAddress         // Source IP address for IPv4 or IPv6
	dip           IPAddress         // Dest IP address for IPv4 or IPv6
	sport         uint16            // Source port for TCP and UDP, typecode for ICMP
	dport         uint16            // Dest port for TCP and UDP
	protocol      layers.IPProtocol // TCP, UDP, ICMP, ICMPv6
	payloadLength uint16            // Number of bytes in application payload
	packetLength  uint16            // Number of bytes in the packet (CaptureInfo.Length)
	tcpFlags      byte              // TCP flags if packet is TCP
	tcpSeq        uint32            // TCP sequence number if packet is TCP
	vlanid        uint16            // VLAN ID for 802.1q (assume zero means no VLAN)
}

func printMetaPacket(mp MetaPacket) {
	fmt.Printf("%s ", mp.timestamp.Format("2006-01-02 15:04:05.00000"))

	switch mp.protocol {
	case layers.IPProtocolTCP:
		fallthrough
	case layers.IPProtocolUDP:
		if mp.sip.Version == 4 {
			fmt.Printf(" %s %s:%d -> %s:%d", mp.protocol.String(), mp.sip.Address, mp.sport,
				mp.dip.Address, mp.dport)
		} else {
			fmt.Printf(" %s %s.%d -> %s.%d", mp.protocol.String(), mp.sip.Address, mp.sport,
				mp.dip.Address, mp.dport)
		}
	case layers.IPProtocolICMPv4:
		fmt.Printf(" %s %s -> %s, typecode: %v", mp.protocol.String(),
			mp.sip.Address, mp.dip.Address, layers.ICMPv4TypeCode(mp.sport).String())
	case layers.IPProtocolICMPv6:
		fmt.Printf(" %s %s -> %s, typecode: %v", mp.protocol.String(),
			mp.sip.Address, mp.dip.Address, layers.ICMPv6TypeCode(mp.sport).String())
	}
	fmt.Printf(", payload: %v", mp.payloadLength)
	fmt.Println("")
}

// Summary statistics variables
var stats struct {
	NumBytes     uint64
	NumDecoded   uint64
	NumTruncated uint64
	TotalPackets uint64
	TotalFlows   uint64
}

// FilterTCPFlags returns true one of the following TCP flag combinations exists.
// 1. SYN FIN.
// 2. A FIN without an ACK flag.
// 4. "Null" packets (no flags set at all).
func FilterTCPFlags(tcp layers.TCP) bool {
	switch {
	case tcp.SYN && tcp.FIN:
		return true
	case !tcp.FIN && !tcp.ACK:
		return true
	case !tcp.FIN && !tcp.SYN && !tcp.RST && !tcp.PSH && !tcp.ACK && !tcp.URG:
		return true
	default:
		return false
	}
}

// GeneratePackets ...
func GeneratePackets(done <-chan struct{}, handle *pcap.Handle) <-chan MetaPacket {
	// Set up a goroutine to handle shutdown signals. This allows the program to gracefully
	// shut down on ^C or SIGTERM.
	inSignal := make(chan os.Signal, 1)
	shutdown := make(chan bool, 1)
	signal.Notify(inSignal, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-inSignal
		fmt.Println("\nReceived ^C. Gracefully shutting down.")
		shutdown <- true
	}()

	out := make(chan MetaPacket, 256)
	go func() {
		defer close(out)
		var mp MetaPacket
		decoded := make([]gopacket.LayerType, 0, numLayers)
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4,
			&ip6, &ipv6ext, &tcp, &udp, &icmp, &icmp6, &dns, &payload)

	Loop:
		for {
			select {
			case <-done:
			case <-shutdown:
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
				stats.TotalPackets++
				if err = parser.DecodeLayers(data, &decoded); err != nil {
					// This error means we have a packet that does not conform to the layers we
					// expected to receive.  That could mean we have something interesting to
					// investigate.
					//
					// TODO: We need to provide an analytic or forensics capability for this case.
					// Bytes in `data` describe the packet and can be dumped to a file for further
					// analysis.
					if config.Debug.PrintErrors {
						log.Println(err)
					}
					continue Loop
				}
				stats.NumDecoded++
				stats.NumBytes += uint64(len(data))

				if parser.Truncated {
					// We have a truncated packet. Skip it for now.
					// NOTE: How should we handle truncated packets?
					stats.NumTruncated++
					//continue Loop
				}

				// We are ready to send a Packet to packetChan, but we need to copy values, not copy
				// references to values. We deep copy the slices we are interested in preserving across
				// the channel.
				// IDEA: This may be a profiling and optimization target.
				mp.id = stats.NumDecoded
				mp.timestamp = ci.Timestamp
				mp.packetLength = uint16(len(data))
				for _, typ := range decoded {
					switch typ {
					case layers.LayerTypeDot1Q:
						mp.vlanid = dot1q.VLANIdentifier
					case layers.LayerTypeIPv4:
						// At this point, we know that 'in' is defragmented.
						mp.sip.Address = ip4.SrcIP.String()
						mp.sip.Version = 4
						mp.dip.Address = ip4.DstIP.String()
						mp.dip.Version = 4
					case layers.LayerTypeIPv6:
						mp.sip.Address = ip6.SrcIP.String()
						mp.sip.Version = 6
						mp.dip.Address = ip6.DstIP.String()
						mp.dip.Version = 6
					case layers.LayerTypeTCP:
						mp.sport = uint16(tcp.SrcPort)
						mp.dport = uint16(tcp.DstPort)
						mp.protocol = layers.IPProtocolTCP
						mp.tcpSeq = tcp.Seq
						mp.tcpFlags = 0x00
						if config.FilterTCPFlags && FilterTCPFlags(tcp) {
							log.Println("Dropping packet with suspicious flags: ", tcp)
							continue Loop
						}
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
					case layers.LayerTypeDNS: // Treat this like a payload
						fallthrough
					case gopacket.LayerTypePayload:
						mp.payloadLength = uint16(len(payload))
					}
				}
				out <- mp
				if config.Debug.PrintPackets {
					printMetaPacket(mp)
				}
				mp.sport = 0
				mp.dport = 0
				mp.protocol = 0
				mp.payloadLength = 0
				mp.tcpFlags = 0
				mp.tcpSeq = 0
				mp.vlanid = 0
			}
		}
		wg.Done()
	}()
	return out
}
