package main

import (
	"testing"

	"github.com/google/gopacket/pcap"
)

// Test cases

// Benchmarks

func BenchmarkProcessPackets(b *testing.B) {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/allFileTypes.pcap")
	verbose = false // Don't output packets for parsing benchmarking
	for i := 0; i < b.N; i++ {
		ProcessPackets(handle)
	}
	handle.Close()
}

// Example test cases

func ExampleProcessPackets_icmp() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/icmp.pcap")
	verbose = true
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 1159744449038238000, ip: 4, sip: 100.10.20.7, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 2, ts: 1159744449038517000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.7, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 3, ts: 1159744449039640000, ip: 4, sip: 100.10.20.7, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 4, ts: 1159744449039729000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.7, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 5, ts: 1159744454398757000, ip: 4, sip: 100.10.20.8, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 6, ts: 1159744454398995000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.8, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 7, ts: 1159744454400133000, ip: 4, sip: 100.10.20.8, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 8, ts: 1159744454400434000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.8, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 9, ts: 1159744460280347000, ip: 4, sip: 100.10.20.10, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 10, ts: 1159744460280570000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.10, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 11, ts: 1159744460281751000, ip: 4, sip: 100.10.20.10, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 12, ts: 1159744460282009000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.10, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 13, ts: 1159744464220302000, ip: 4, sip: 100.10.20.9, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 14, ts: 1159744464220601000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.9, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 15, ts: 1159744464221652000, ip: 4, sip: 100.10.20.9, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 16, ts: 1159744464221801000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.9, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 17, ts: 1159744498196762000, ip: 4, sip: 100.10.20.12, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 18, ts: 1159744498196922000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.12, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 19, ts: 1159744498197410000, ip: 4, sip: 100.10.20.12, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 20, ts: 1159744498197620000, ip: 4, sip: 100.10.20.3, dip: 100.10.20.12, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 21, ts: 1159744749057429000, ip: 4, sip: 100.10.20.4, dip: 100.20.1.3, proto: ICMPv4, typecode: DestinationUnreachable(Port), payload: 28}
	// {id: 22, ts: 1159744749057671000, ip: 4, sip: 100.10.20.4, dip: 100.20.1.3, proto: ICMPv4, typecode: DestinationUnreachable(Port), payload: 28}
	// {id: 23, ts: 1159744749121648000, ip: 4, sip: 100.10.20.4, dip: 100.20.1.3, proto: ICMPv4, typecode: DestinationUnreachable(Port), payload: 28}
	// Processed 23 packets (1690 bytes) with 23 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_tcpCompleteV4() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v4.pcap")
	verbose = true
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 1240866004066108000, ip: 4, sip: 192.168.0.5, dip: 192.168.0.7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 2, ts: 1240866004084535000, ip: 4, sip: 192.168.0.7, dip: 192.168.0.5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// {id: 3, ts: 1240866004084578000, ip: 4, sip: 192.168.0.5, dip: 192.168.0.7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 4, ts: 1240866007173911000, ip: 4, sip: 192.168.0.5, dip: 192.168.0.7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 5, ts: 1240866007173944000, ip: 4, sip: 192.168.0.7, dip: 192.168.0.5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// Processed 5 packets (292 bytes) with 5 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_tcpCompleteV6() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v6.pcap")
	verbose = true
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 1240887423691500000, ip: 6, sip: fe80::5, dip: fe80::7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 2, ts: 1240887423693061000, ip: 6, sip: fe80::7, dip: fe80::5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// {id: 3, ts: 1240887423694612000, ip: 6, sip: fe80::5, dip: fe80::7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 4, ts: 1240887423696151000, ip: 6, sip: fe80::5, dip: fe80::7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 5, ts: 1240887423697700000, ip: 6, sip: fe80::7, dip: fe80::5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// Processed 5 packets (392 bytes) with 5 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_vlan() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/vlan.pcap")
	verbose = true
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 941826040056226000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 2, ts: 941826040056331000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 580}
	// {id: 3, ts: 941826040063897000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 4, ts: 941826040063982000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 280}
	// {id: 5, ts: 941826040064555000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 280}
	// {id: 6, ts: 941826040065843000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 1448}
	// {id: 7, ts: 941826040065888000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 568}
	// {id: 8, ts: 941826040066028000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 568}
	// {id: 9, ts: 941826040066114000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 568}
	// {id: 10, ts: 941826040070364000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 1024}
	// {id: 11, ts: 941826040070512000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1024}
	// {id: 12, ts: 941826040071541000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 13, ts: 941826040074903000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 156}
	// {id: 14, ts: 941826040075421000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 112}
	// {id: 15, ts: 941826040076526000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 264}
	// {id: 16, ts: 941826040077081000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 17, ts: 941826040077584000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 112}
	// {id: 18, ts: 941826040081942000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 264}
	// {id: 19, ts: 941826040082556000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 20, ts: 941826040083441000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 21, ts: 941826040084469000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 22, ts: 941826040085324000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 23, ts: 941826040086151000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 24, ts: 941826040086966000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 25, ts: 941826040087264000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 344}
	// {id: 26, ts: 941826040088088000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 516}
	// {id: 27, ts: 941826040090343000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 28, ts: 941826040091093000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 29, ts: 941826040091699000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 30, ts: 941826040092366000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 31, ts: 941826040093097000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 516}
	// {id: 32, ts: 941826040094035000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 33, ts: 941826040094360000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 34, ts: 941826040094588000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 35, ts: 941826040098181000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 8}
	// {id: 36, ts: 941826040098438000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 32}
	// {id: 37, ts: 941826040104421000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 192}
	// {id: 38, ts: 941826040106347000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 448}
	// {id: 39, ts: 941826040112031000, ip: 4, sip: 131.151.5.55, dip: 131.151.5.255, proto: UDP, sport: 138, dport: 138, payload: 201}
	// {id: 40, ts: 941826040112992000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 532}
	// {id: 41, ts: 941826040114867000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 832}
	// {id: 42, ts: 941826040116210000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 104}
	// {id: 43, ts: 941826040117247000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 44, ts: 941826040117922000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 45, ts: 941826040162350000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 128}
	// {id: 46, ts: 941826040178702000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 128}
	// {id: 47, ts: 941826040258261000, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 48, ts: 941826040258417000, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 49, ts: 941826040829427000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 32}
	// {id: 50, ts: 941826040848740000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 32}
	// {id: 51, ts: 941826040848711000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 52, ts: 941826040851014000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 53, ts: 941826040859213000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 128}
	// {id: 54, ts: 941826040861199000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 55, ts: 941826040880427000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 56, ts: 941826040999300000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 128}
	// {id: 57, ts: 941826041001089000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 58, ts: 941826041009011000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 128}
	// {id: 59, ts: 941826041011210000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 60, ts: 941826041018833000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 61, ts: 941826041038753000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 96}
	// {id: 62, ts: 941826041088508000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 63, ts: 941826041088595000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 64, ts: 941826041091023000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 65, ts: 941826041091110000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 640}
	// {id: 66, ts: 941826041091221000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 588}
	// {id: 67, ts: 941826041092353000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 68, ts: 941826041092425000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 69, ts: 941826041093005000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 592}
	// {id: 70, ts: 941826041093707000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 71, ts: 941826041093776000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 72, ts: 941826041094859000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 73, ts: 941826041094931000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 74, ts: 941826041095323000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 176}
	// {id: 75, ts: 941826041095500000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 176}
	// {id: 76, ts: 941826041097629000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 77, ts: 941826041098407000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 78, ts: 941826041100442000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 79, ts: 941826041101236000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 80, ts: 941826041102582000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 104}
	// {id: 81, ts: 941826041103006000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 82, ts: 941826041103405000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 20}
	// {id: 83, ts: 941826041104631000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 84, ts: 941826041106113000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 224}
	// {id: 85, ts: 941826041106731000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 16}
	// {id: 86, ts: 941826041107234000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 87, ts: 941826041110429000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 32}
	// {id: 88, ts: 941826041110804000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 89, ts: 941826041111199000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 64}
	// {id: 90, ts: 941826041112408000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 1448}
	// {id: 91, ts: 941826041112477000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 24}
	// {id: 92, ts: 941826041113347000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 824}
	// {id: 93, ts: 941826041115390000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 1448}
	// {id: 94, ts: 941826041115467000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 588}
	// {id: 95, ts: 941826041115895000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 260}
	// {id: 96, ts: 941826041116047000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 260}
	// {id: 97, ts: 941826041130430000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 260}
	// {id: 98, ts: 941826041257879000, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 99, ts: 941826041258037000, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 100, ts: 941826041521798000, ip: 4, sip: 131.151.104.96, dip: 131.151.107.255, proto: UDP, sport: 137, dport: 137, payload: 50}
	// {id: 101, ts: 941826042063074000, ip: 4, sip: 131.151.32.71, dip: 131.151.32.255, proto: UDP, sport: 138, dport: 138, payload: 201}
	// {id: 102, ts: 941826042107717000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 103, ts: 941826042107799000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 104, ts: 941826042110292000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 105, ts: 941826042110361000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 588}
	// {id: 106, ts: 941826042110477000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 448}
	// {id: 107, ts: 941826042111634000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 108, ts: 941826042111704000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 600}
	// {id: 109, ts: 941826042112293000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 600}
	// {id: 110, ts: 941826042112922000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 111, ts: 941826042112988000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 112, ts: 941826042114027000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 113, ts: 941826042114090000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 92}
	// {id: 114, ts: 941826042114659000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 92}
	// {id: 115, ts: 941826042115684000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 116, ts: 941826042116456000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 117, ts: 941826042117083000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 118, ts: 941826042117860000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 119, ts: 941826042120430000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 8}
	// {id: 120, ts: 941826042120938000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 121, ts: 941826042121783000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 122, ts: 941826042122841000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 123, ts: 941826042130407000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 468}
	// {id: 124, ts: 941826042140401000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 468}
	// {id: 125, ts: 941826042199706000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 126, ts: 941826042209236000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 127, ts: 941826042218756000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 64}
	// {id: 128, ts: 941826042257877000, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 129, ts: 941826042258046000, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 130, ts: 941826042259302000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 131, ts: 941826042269828000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 132, ts: 941826042272762000, ip: 4, sip: 131.151.104.96, dip: 131.151.107.255, proto: UDP, sport: 137, dport: 137, payload: 50}
	// {id: 133, ts: 941826042278752000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 50}
	// {id: 134, ts: 941826042279454000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 135, ts: 941826042289986000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 136, ts: 941826042290810000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 137, ts: 941826042310420000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 138, ts: 941826042319989000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 139, ts: 941826042320821000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 140, ts: 941826042329424000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 141, ts: 941826042348769000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 64}
	// {id: 142, ts: 941826042349500000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 143, ts: 941826042368768000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 64}
	// {id: 144, ts: 941826042490316000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 145, ts: 941826042499668000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 146, ts: 941826042508781000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 32}
	// {id: 147, ts: 941826042518770000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 32}
	// {id: 148, ts: 941826042519688000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 64}
	// {id: 149, ts: 941826042521978000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 824}
	// {id: 150, ts: 941826042718769000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 824}
	// {id: 151, ts: 941826042719225000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 824}
	// {id: 152, ts: 941826043023840000, ip: 4, sip: 131.151.104.96, dip: 131.151.107.255, proto: UDP, sport: 137, dport: 137, payload: 50}
	// {id: 153, ts: 941826043079765000, ip: 4, sip: 131.151.5.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 154, ts: 941826043083399000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 155, ts: 941826043083487000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 156, ts: 941826043084581000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 157, ts: 941826043084654000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 158, ts: 941826043085236000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 584}
	// {id: 159, ts: 941826043085937000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 160, ts: 941826043086006000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 161, ts: 941826043086398000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 162, ts: 941826043087010000, ip: 4, sip: 131.151.6.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 163, ts: 941826043087385000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 164, ts: 941826043087457000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 165, ts: 941826043088040000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 596}
	// {id: 166, ts: 941826043088501000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1080}
	// {id: 167, ts: 941826043090869000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 168, ts: 941826043092070000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 8}
	// {id: 169, ts: 941826043093954000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 170, ts: 941826043094735000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 171, ts: 941826043095815000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 172, ts: 941826043096540000, ip: 4, sip: 131.151.1.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 173, ts: 941826043100397000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 24}
	// {id: 174, ts: 941826043110422000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 24}
	// {id: 175, ts: 941826043115330000, ip: 4, sip: 131.151.10.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 176, ts: 941826043170500000, ip: 4, sip: 131.151.20.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 177, ts: 941826043183825000, ip: 4, sip: 131.151.32.79, dip: 131.151.32.255, proto: UDP, sport: 138, dport: 138, payload: 201}
	// {id: 178, ts: 941826043250410000, ip: 4, sip: 131.151.32.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 179, ts: 941826043257880000, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 180, ts: 941826043258029000, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 181, ts: 941826043363348000, ip: 4, sip: 131.151.107.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 182, ts: 941826043368210000, ip: 4, sip: 131.151.111.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 183, ts: 941826043375145000, ip: 4, sip: 131.151.115.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 184, ts: 941826044091156000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 8}
	// {id: 185, ts: 941826044091452000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 186, ts: 941826044100780000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 187, ts: 941826044101881000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 188, ts: 941826044103511000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 189, ts: 941826044103590000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 190, ts: 941826044105245000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 191, ts: 941826044105321000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 192, ts: 941826044105905000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 584}
	// {id: 193, ts: 941826044106466000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 194, ts: 941826044107923000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 195, ts: 941826044108000000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 196, ts: 941826044110974000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 197, ts: 941826044111050000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 198, ts: 941826044111629000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 596}
	// {id: 199, ts: 941826044113052000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1080}
	// {id: 200, ts: 941826044114318000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 201, ts: 941826044120380000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 132}
	// {id: 202, ts: 941826044130376000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 203, ts: 941826044257898000, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 204, ts: 941826044258042000, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 205, ts: 941826044420890000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 206, ts: 941826044423001000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 880}
	// {id: 207, ts: 941826044423821000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 880}
	// {id: 208, ts: 941826044424281000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 880}
	// {id: 209, ts: 941826044501093000, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 210, ts: 941826044502622000, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 880}
	// Processed 395 packets (101663 bytes) with 210 decoded, 185 errors, and 0 truncated.
}
