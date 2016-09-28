package main

import "github.com/google/gopacket/pcap"

// Test cases

// Benchmarks

// Example test cases

func ExampleProcessPackets_icmp() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/icmp.pcap")

	// CL options
	DebugPrintPackets = true
	DebugPrintFlows = false
	ActiveTimeout = 1800
	IdleTimeout = 63

	// State
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	totalFlows = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 2006-10-01 18:14:09.038238 -0500 CDT, ip: 4, sip: 100.10.20.7, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 2, ts: 2006-10-01 18:14:09.038517 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.7, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 3, ts: 2006-10-01 18:14:09.03964 -0500 CDT, ip: 4, sip: 100.10.20.7, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 4, ts: 2006-10-01 18:14:09.039729 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.7, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 5, ts: 2006-10-01 18:14:14.398757 -0500 CDT, ip: 4, sip: 100.10.20.8, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 6, ts: 2006-10-01 18:14:14.398995 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.8, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 7, ts: 2006-10-01 18:14:14.400133 -0500 CDT, ip: 4, sip: 100.10.20.8, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 8, ts: 2006-10-01 18:14:14.400434 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.8, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 9, ts: 2006-10-01 18:14:20.280347 -0500 CDT, ip: 4, sip: 100.10.20.10, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 10, ts: 2006-10-01 18:14:20.28057 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.10, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 11, ts: 2006-10-01 18:14:20.281751 -0500 CDT, ip: 4, sip: 100.10.20.10, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 12, ts: 2006-10-01 18:14:20.282009 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.10, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 13, ts: 2006-10-01 18:14:24.220302 -0500 CDT, ip: 4, sip: 100.10.20.9, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 14, ts: 2006-10-01 18:14:24.220601 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.9, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 15, ts: 2006-10-01 18:14:24.221652 -0500 CDT, ip: 4, sip: 100.10.20.9, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 16, ts: 2006-10-01 18:14:24.221801 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.9, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 17, ts: 2006-10-01 18:14:58.196762 -0500 CDT, ip: 4, sip: 100.10.20.12, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 18, ts: 2006-10-01 18:14:58.196922 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.12, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 19, ts: 2006-10-01 18:14:58.19741 -0500 CDT, ip: 4, sip: 100.10.20.12, dip: 100.10.20.3, proto: ICMPv4, typecode: EchoRequest, payload: 32}
	// {id: 20, ts: 2006-10-01 18:14:58.19762 -0500 CDT, ip: 4, sip: 100.10.20.3, dip: 100.10.20.12, proto: ICMPv4, typecode: EchoReply, payload: 32}
	// {id: 21, ts: 2006-10-01 18:19:09.057429 -0500 CDT, ip: 4, sip: 100.10.20.4, dip: 100.20.1.3, proto: ICMPv4, typecode: DestinationUnreachable(Port), payload: 28}
	// {id: 22, ts: 2006-10-01 18:19:09.057671 -0500 CDT, ip: 4, sip: 100.10.20.4, dip: 100.20.1.3, proto: ICMPv4, typecode: DestinationUnreachable(Port), payload: 28}
	// {id: 23, ts: 2006-10-01 18:19:09.121648 -0500 CDT, ip: 4, sip: 100.10.20.4, dip: 100.20.1.3, proto: ICMPv4, typecode: DestinationUnreachable(Port), payload: 28}
	// Processed 23 packets (1690 bytes) in 11 flows with 23 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_icmp6EchoRequest() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/icmp6-echo-request.pcap")

	// CL options
	DebugPrintPackets = true
	DebugPrintFlows = false
	ActiveTimeout = 1800
	IdleTimeout = 63

	// State
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	totalFlows = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 2008-11-26 14:06:11.994161 -0600 CST, ip: 6, sip: ::, dip: ff02::1, proto: ICMPv6, typecode: EchoRequest, payload: 0}
	// {id: 2, ts: 2008-11-26 14:06:11.994421 -0600 CST, ip: 6, sip: ff02::1, dip: ::, proto: ICMPv6, typecode: EchoReply, payload: 0}
	// Processed 2 packets (124 bytes) in 2 flows with 2 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_tcpCompleteV4() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v4.pcap")

	// CL options
	DebugPrintPackets = true
	DebugPrintFlows = false
	ActiveTimeout = 1800
	IdleTimeout = 63

	// State
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	totalFlows = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 2009-04-27 16:00:04.066108 -0500 CDT, ip: 4, sip: 192.168.0.5, dip: 192.168.0.7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 2, ts: 2009-04-27 16:00:04.084535 -0500 CDT, ip: 4, sip: 192.168.0.7, dip: 192.168.0.5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// {id: 3, ts: 2009-04-27 16:00:04.084578 -0500 CDT, ip: 4, sip: 192.168.0.5, dip: 192.168.0.7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 4, ts: 2009-04-27 16:00:07.173911 -0500 CDT, ip: 4, sip: 192.168.0.5, dip: 192.168.0.7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 5, ts: 2009-04-27 16:00:07.173944 -0500 CDT, ip: 4, sip: 192.168.0.7, dip: 192.168.0.5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// Processed 5 packets (292 bytes) in 2 flows with 5 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_tcpCompleteV6() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v6.pcap")

	// CL options
	DebugPrintPackets = true
	DebugPrintFlows = false
	ActiveTimeout = 1800
	IdleTimeout = 63

	// State
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	totalFlows = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 2009-04-27 21:57:03.6915 -0500 CDT, ip: 6, sip: fe80::5, dip: fe80::7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 2, ts: 2009-04-27 21:57:03.693061 -0500 CDT, ip: 6, sip: fe80::7, dip: fe80::5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// {id: 3, ts: 2009-04-27 21:57:03.694612 -0500 CDT, ip: 6, sip: fe80::5, dip: fe80::7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 4, ts: 2009-04-27 21:57:03.696151 -0500 CDT, ip: 6, sip: fe80::5, dip: fe80::7, proto: TCP, sport: 1449, dport: 2111, payload: 0}
	// {id: 5, ts: 2009-04-27 21:57:03.6977 -0500 CDT, ip: 6, sip: fe80::7, dip: fe80::5, proto: TCP, sport: 2111, dport: 1449, payload: 0}
	// Processed 5 packets (392 bytes) in 2 flows with 5 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_vlan() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/vlan.pcap")

	// CL options
	DebugPrintPackets = true
	DebugPrintFlows = false
	ActiveTimeout = 1800
	IdleTimeout = 63

	// State
	numBytes = 0
	numDecoded = 0
	numErrors = 0
	numTruncated = 0
	totalPackets = 0
	totalFlows = 0
	ProcessPackets(handle)
	handle.Close()
	// Output:
	// {id: 1, ts: 1999-11-05 12:20:40.056226 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 2, ts: 1999-11-05 12:20:40.056331 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 580}
	// {id: 3, ts: 1999-11-05 12:20:40.063897 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 4, ts: 1999-11-05 12:20:40.063982 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 280}
	// {id: 5, ts: 1999-11-05 12:20:40.064555 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 280}
	// {id: 6, ts: 1999-11-05 12:20:40.065843 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 1448}
	// {id: 7, ts: 1999-11-05 12:20:40.065888 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 568}
	// {id: 8, ts: 1999-11-05 12:20:40.066028 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 568}
	// {id: 9, ts: 1999-11-05 12:20:40.066114 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 568}
	// {id: 10, ts: 1999-11-05 12:20:40.070364 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 1024}
	// {id: 11, ts: 1999-11-05 12:20:40.070512 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1024}
	// {id: 12, ts: 1999-11-05 12:20:40.071541 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 13, ts: 1999-11-05 12:20:40.074903 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 156}
	// {id: 14, ts: 1999-11-05 12:20:40.075421 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 112}
	// {id: 15, ts: 1999-11-05 12:20:40.076526 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 264}
	// {id: 16, ts: 1999-11-05 12:20:40.077081 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 17, ts: 1999-11-05 12:20:40.077584 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 112}
	// {id: 18, ts: 1999-11-05 12:20:40.081942 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 264}
	// {id: 19, ts: 1999-11-05 12:20:40.082556 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 20, ts: 1999-11-05 12:20:40.083441 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 21, ts: 1999-11-05 12:20:40.084469 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 22, ts: 1999-11-05 12:20:40.085324 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 23, ts: 1999-11-05 12:20:40.086151 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 24, ts: 1999-11-05 12:20:40.086966 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 25, ts: 1999-11-05 12:20:40.087264 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 344}
	// {id: 26, ts: 1999-11-05 12:20:40.088088 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 516}
	// {id: 27, ts: 1999-11-05 12:20:40.090343 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 28, ts: 1999-11-05 12:20:40.091093 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 29, ts: 1999-11-05 12:20:40.091699 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 30, ts: 1999-11-05 12:20:40.092366 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 344}
	// {id: 31, ts: 1999-11-05 12:20:40.093097 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 516}
	// {id: 32, ts: 1999-11-05 12:20:40.094035 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 33, ts: 1999-11-05 12:20:40.09436 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 34, ts: 1999-11-05 12:20:40.094588 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 35, ts: 1999-11-05 12:20:40.098181 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 8}
	// {id: 36, ts: 1999-11-05 12:20:40.098438 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 32}
	// {id: 37, ts: 1999-11-05 12:20:40.104421 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 192}
	// {id: 38, ts: 1999-11-05 12:20:40.106347 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 448}
	// {id: 39, ts: 1999-11-05 12:20:40.112031 -0600 CST, ip: 4, sip: 131.151.5.55, dip: 131.151.5.255, proto: UDP, sport: 138, dport: 138, payload: 201}
	// {id: 40, ts: 1999-11-05 12:20:40.112992 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 532}
	// {id: 41, ts: 1999-11-05 12:20:40.114867 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 832}
	// {id: 42, ts: 1999-11-05 12:20:40.11621 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 104}
	// {id: 43, ts: 1999-11-05 12:20:40.117247 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 44, ts: 1999-11-05 12:20:40.117922 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 45, ts: 1999-11-05 12:20:40.16235 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 128}
	// {id: 46, ts: 1999-11-05 12:20:40.178702 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 128}
	// {id: 47, ts: 1999-11-05 12:20:40.258261 -0600 CST, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 48, ts: 1999-11-05 12:20:40.258417 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 49, ts: 1999-11-05 12:20:40.829427 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 32}
	// {id: 50, ts: 1999-11-05 12:20:40.84874 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 32}
	// {id: 51, ts: 1999-11-05 12:20:40.848711 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 52, ts: 1999-11-05 12:20:40.851014 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 53, ts: 1999-11-05 12:20:40.859213 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 128}
	// {id: 54, ts: 1999-11-05 12:20:40.861199 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 55, ts: 1999-11-05 12:20:40.880427 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 56, ts: 1999-11-05 12:20:40.9993 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 128}
	// {id: 57, ts: 1999-11-05 12:20:41.001089 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 58, ts: 1999-11-05 12:20:41.009011 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 128}
	// {id: 59, ts: 1999-11-05 12:20:41.01121 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 60, ts: 1999-11-05 12:20:41.018833 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 61, ts: 1999-11-05 12:20:41.038753 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 96}
	// {id: 62, ts: 1999-11-05 12:20:41.088508 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 63, ts: 1999-11-05 12:20:41.088595 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 64, ts: 1999-11-05 12:20:41.091023 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 65, ts: 1999-11-05 12:20:41.09111 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 640}
	// {id: 66, ts: 1999-11-05 12:20:41.091221 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 588}
	// {id: 67, ts: 1999-11-05 12:20:41.092353 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 68, ts: 1999-11-05 12:20:41.092425 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 69, ts: 1999-11-05 12:20:41.093005 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 592}
	// {id: 70, ts: 1999-11-05 12:20:41.093707 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 71, ts: 1999-11-05 12:20:41.093776 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 72, ts: 1999-11-05 12:20:41.094859 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 73, ts: 1999-11-05 12:20:41.094931 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 74, ts: 1999-11-05 12:20:41.095323 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 176}
	// {id: 75, ts: 1999-11-05 12:20:41.0955 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 176}
	// {id: 76, ts: 1999-11-05 12:20:41.097629 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 77, ts: 1999-11-05 12:20:41.098407 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 78, ts: 1999-11-05 12:20:41.100442 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 79, ts: 1999-11-05 12:20:41.101236 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 80, ts: 1999-11-05 12:20:41.102582 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 104}
	// {id: 81, ts: 1999-11-05 12:20:41.103006 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 82, ts: 1999-11-05 12:20:41.103405 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 20}
	// {id: 83, ts: 1999-11-05 12:20:41.104631 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 84, ts: 1999-11-05 12:20:41.106113 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 224}
	// {id: 85, ts: 1999-11-05 12:20:41.106731 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 16}
	// {id: 86, ts: 1999-11-05 12:20:41.107234 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 87, ts: 1999-11-05 12:20:41.110429 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 32}
	// {id: 88, ts: 1999-11-05 12:20:41.110804 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 89, ts: 1999-11-05 12:20:41.111199 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 64}
	// {id: 90, ts: 1999-11-05 12:20:41.112408 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 1448}
	// {id: 91, ts: 1999-11-05 12:20:41.112477 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 24}
	// {id: 92, ts: 1999-11-05 12:20:41.113347 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 824}
	// {id: 93, ts: 1999-11-05 12:20:41.11539 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 1448}
	// {id: 94, ts: 1999-11-05 12:20:41.115467 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 588}
	// {id: 95, ts: 1999-11-05 12:20:41.115895 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 260}
	// {id: 96, ts: 1999-11-05 12:20:41.116047 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 260}
	// {id: 97, ts: 1999-11-05 12:20:41.13043 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 260}
	// {id: 98, ts: 1999-11-05 12:20:41.257879 -0600 CST, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 99, ts: 1999-11-05 12:20:41.258037 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 100, ts: 1999-11-05 12:20:41.521798 -0600 CST, ip: 4, sip: 131.151.104.96, dip: 131.151.107.255, proto: UDP, sport: 137, dport: 137, payload: 50}
	// {id: 101, ts: 1999-11-05 12:20:42.063074 -0600 CST, ip: 4, sip: 131.151.32.71, dip: 131.151.32.255, proto: UDP, sport: 138, dport: 138, payload: 201}
	// {id: 102, ts: 1999-11-05 12:20:42.107717 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 103, ts: 1999-11-05 12:20:42.107799 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 104, ts: 1999-11-05 12:20:42.110292 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 105, ts: 1999-11-05 12:20:42.110361 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 588}
	// {id: 106, ts: 1999-11-05 12:20:42.110477 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 448}
	// {id: 107, ts: 1999-11-05 12:20:42.111634 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 108, ts: 1999-11-05 12:20:42.111704 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 600}
	// {id: 109, ts: 1999-11-05 12:20:42.112293 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 600}
	// {id: 110, ts: 1999-11-05 12:20:42.112922 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 111, ts: 1999-11-05 12:20:42.112988 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 112, ts: 1999-11-05 12:20:42.114027 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 113, ts: 1999-11-05 12:20:42.11409 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 92}
	// {id: 114, ts: 1999-11-05 12:20:42.114659 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 92}
	// {id: 115, ts: 1999-11-05 12:20:42.115684 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 116, ts: 1999-11-05 12:20:42.116456 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 117, ts: 1999-11-05 12:20:42.117083 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 118, ts: 1999-11-05 12:20:42.11786 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 512}
	// {id: 119, ts: 1999-11-05 12:20:42.12043 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 8}
	// {id: 120, ts: 1999-11-05 12:20:42.120938 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 121, ts: 1999-11-05 12:20:42.121783 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 122, ts: 1999-11-05 12:20:42.122841 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 123, ts: 1999-11-05 12:20:42.130407 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 468}
	// {id: 124, ts: 1999-11-05 12:20:42.140401 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 468}
	// {id: 125, ts: 1999-11-05 12:20:42.199706 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 126, ts: 1999-11-05 12:20:42.209236 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 127, ts: 1999-11-05 12:20:42.218756 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 64}
	// {id: 128, ts: 1999-11-05 12:20:42.257877 -0600 CST, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 129, ts: 1999-11-05 12:20:42.258046 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 130, ts: 1999-11-05 12:20:42.259302 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 131, ts: 1999-11-05 12:20:42.269828 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 132, ts: 1999-11-05 12:20:42.272762 -0600 CST, ip: 4, sip: 131.151.104.96, dip: 131.151.107.255, proto: UDP, sport: 137, dport: 137, payload: 50}
	// {id: 133, ts: 1999-11-05 12:20:42.278752 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 50}
	// {id: 134, ts: 1999-11-05 12:20:42.279454 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 135, ts: 1999-11-05 12:20:42.289986 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 136, ts: 1999-11-05 12:20:42.29081 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 137, ts: 1999-11-05 12:20:42.31042 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 138, ts: 1999-11-05 12:20:42.319989 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 139, ts: 1999-11-05 12:20:42.320821 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 140, ts: 1999-11-05 12:20:42.329424 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 141, ts: 1999-11-05 12:20:42.348769 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 64}
	// {id: 142, ts: 1999-11-05 12:20:42.3495 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 64}
	// {id: 143, ts: 1999-11-05 12:20:42.368768 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 64}
	// {id: 144, ts: 1999-11-05 12:20:42.490316 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 145, ts: 1999-11-05 12:20:42.499668 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 146, ts: 1999-11-05 12:20:42.508781 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 32}
	// {id: 147, ts: 1999-11-05 12:20:42.51877 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 32}
	// {id: 148, ts: 1999-11-05 12:20:42.519688 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 64}
	// {id: 149, ts: 1999-11-05 12:20:42.521978 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 824}
	// {id: 150, ts: 1999-11-05 12:20:42.718769 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 824}
	// {id: 151, ts: 1999-11-05 12:20:42.719225 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 824}
	// {id: 152, ts: 1999-11-05 12:20:43.02384 -0600 CST, ip: 4, sip: 131.151.104.96, dip: 131.151.107.255, proto: UDP, sport: 137, dport: 137, payload: 50}
	// {id: 153, ts: 1999-11-05 12:20:43.079765 -0600 CST, ip: 4, sip: 131.151.5.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 154, ts: 1999-11-05 12:20:43.083399 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 155, ts: 1999-11-05 12:20:43.083487 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 156, ts: 1999-11-05 12:20:43.084581 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 157, ts: 1999-11-05 12:20:43.084654 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 158, ts: 1999-11-05 12:20:43.085236 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 584}
	// {id: 159, ts: 1999-11-05 12:20:43.085937 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 160, ts: 1999-11-05 12:20:43.086006 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 161, ts: 1999-11-05 12:20:43.086398 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 162, ts: 1999-11-05 12:20:43.08701 -0600 CST, ip: 4, sip: 131.151.6.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 163, ts: 1999-11-05 12:20:43.087385 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 164, ts: 1999-11-05 12:20:43.087457 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 165, ts: 1999-11-05 12:20:43.08804 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 596}
	// {id: 166, ts: 1999-11-05 12:20:43.088501 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1080}
	// {id: 167, ts: 1999-11-05 12:20:43.090869 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 168, ts: 1999-11-05 12:20:43.09207 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 8}
	// {id: 169, ts: 1999-11-05 12:20:43.093954 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 170, ts: 1999-11-05 12:20:43.094735 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 171, ts: 1999-11-05 12:20:43.095815 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 172, ts: 1999-11-05 12:20:43.09654 -0600 CST, ip: 4, sip: 131.151.1.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 173, ts: 1999-11-05 12:20:43.100397 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 24}
	// {id: 174, ts: 1999-11-05 12:20:43.110422 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 24}
	// {id: 175, ts: 1999-11-05 12:20:43.11533 -0600 CST, ip: 4, sip: 131.151.10.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 176, ts: 1999-11-05 12:20:43.1705 -0600 CST, ip: 4, sip: 131.151.20.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 177, ts: 1999-11-05 12:20:43.183825 -0600 CST, ip: 4, sip: 131.151.32.79, dip: 131.151.32.255, proto: UDP, sport: 138, dport: 138, payload: 201}
	// {id: 178, ts: 1999-11-05 12:20:43.25041 -0600 CST, ip: 4, sip: 131.151.32.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 179, ts: 1999-11-05 12:20:43.25788 -0600 CST, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 180, ts: 1999-11-05 12:20:43.258029 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 181, ts: 1999-11-05 12:20:43.363348 -0600 CST, ip: 4, sip: 131.151.107.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 182, ts: 1999-11-05 12:20:43.36821 -0600 CST, ip: 4, sip: 131.151.111.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 183, ts: 1999-11-05 12:20:43.375145 -0600 CST, ip: 4, sip: 131.151.115.254, dip: 255.255.255.255, proto: UDP, sport: 520, dport: 520, payload: 24}
	// {id: 184, ts: 1999-11-05 12:20:44.091156 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 8}
	// {id: 185, ts: 1999-11-05 12:20:44.091452 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 186, ts: 1999-11-05 12:20:44.10078 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 28}
	// {id: 187, ts: 1999-11-05 12:20:44.101881 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 468}
	// {id: 188, ts: 1999-11-05 12:20:44.103511 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 189, ts: 1999-11-05 12:20:44.10359 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 190, ts: 1999-11-05 12:20:44.105245 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 191, ts: 1999-11-05 12:20:44.105321 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 584}
	// {id: 192, ts: 1999-11-05 12:20:44.105905 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 584}
	// {id: 193, ts: 1999-11-05 12:20:44.106466 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 96}
	// {id: 194, ts: 1999-11-05 12:20:44.107923 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 195, ts: 1999-11-05 12:20:44.108 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 592}
	// {id: 196, ts: 1999-11-05 12:20:44.110974 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1448}
	// {id: 197, ts: 1999-11-05 12:20:44.11105 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 596}
	// {id: 198, ts: 1999-11-05 12:20:44.111629 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 596}
	// {id: 199, ts: 1999-11-05 12:20:44.113052 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 1080}
	// {id: 200, ts: 1999-11-05 12:20:44.114318 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1162, dport: 6000, payload: 132}
	// {id: 201, ts: 1999-11-05 12:20:44.12038 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 132}
	// {id: 202, ts: 1999-11-05 12:20:44.130376 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1162, payload: 132}
	// {id: 203, ts: 1999-11-05 12:20:44.257898 -0600 CST, ip: 4, sip: 131.151.6.171, dip: 131.151.32.129, proto: ICMPv4, typecode: EchoRequest, payload: 1469}
	// {id: 204, ts: 1999-11-05 12:20:44.258042 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.6.171, proto: ICMPv4, typecode: EchoReply, payload: 1469}
	// {id: 205, ts: 1999-11-05 12:20:44.42089 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 206, ts: 1999-11-05 12:20:44.423001 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 880}
	// {id: 207, ts: 1999-11-05 12:20:44.423821 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 880}
	// {id: 208, ts: 1999-11-05 12:20:44.424281 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 880}
	// {id: 209, ts: 1999-11-05 12:20:44.501093 -0600 CST, ip: 4, sip: 131.151.32.21, dip: 131.151.32.129, proto: TCP, sport: 6000, dport: 1173, payload: 32}
	// {id: 210, ts: 1999-11-05 12:20:44.502622 -0600 CST, ip: 4, sip: 131.151.32.129, dip: 131.151.32.21, proto: TCP, sport: 1173, dport: 6000, payload: 880}
	// Processed 395 packets (101663 bytes) in 19 flows with 210 decoded, 185 errors, and 0 truncated.
}
