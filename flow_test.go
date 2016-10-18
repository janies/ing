package main

import (
	"testing"

	"github.com/google/gopacket/pcap"
)

// Testing

// Benchmarks

func BenchmarkFlows(b *testing.B) {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/allFileTypes.pcap")
	DebugPrintPackets = false // Don't output packets for parsing benchmarking
	for i := 0; i < b.N; i++ {
		ProcessPackets(handle)
	}
	handle.Close()
}

// Examples
func ExampleProcessPackets_flow_icmp() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/icmp.pcap")

	// CL options
	DebugPrintPackets = false
	DebugPrintFlows = true
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
	// {flow_id: 5, ip4, 100.10.20.10:2048 -> 100.10.20.3:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:20.280347 -0500 CDT, end: 2006-10-01 18:14:20.281751 -0500 CDT}
	// {flow_id: 7, ip4, 100.10.20.9:2048 -> 100.10.20.3:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:24.220302 -0500 CDT, end: 2006-10-01 18:14:24.221652 -0500 CDT}
	// {flow_id: 4, ip4, 100.10.20.3:0 -> 100.10.20.8:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:14.398995 -0500 CDT, end: 2006-10-01 18:14:14.400434 -0500 CDT}
	// {flow_id: 9, ip4, 100.10.20.12:2048 -> 100.10.20.3:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:58.196762 -0500 CDT, end: 2006-10-01 18:14:58.19741 -0500 CDT}
	// {flow_id: 1, ip4, 100.10.20.7:2048 -> 100.10.20.3:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:09.038238 -0500 CDT, end: 2006-10-01 18:14:09.03964 -0500 CDT}
	// {flow_id: 11, ip4, 100.10.20.4:771 -> 100.20.1.3:0, proto: 1, count: 3, bytes: 210, payload_bytes: 84, start: 2006-10-01 18:19:09.057429 -0500 CDT, end: 2006-10-01 18:19:09.121648 -0500 CDT}
	// {flow_id: 2, ip4, 100.10.20.3:0 -> 100.10.20.7:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:09.038517 -0500 CDT, end: 2006-10-01 18:14:09.039729 -0500 CDT}
	// {flow_id: 6, ip4, 100.10.20.3:0 -> 100.10.20.10:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:20.28057 -0500 CDT, end: 2006-10-01 18:14:20.282009 -0500 CDT}
	// {flow_id: 8, ip4, 100.10.20.3:0 -> 100.10.20.9:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:24.220601 -0500 CDT, end: 2006-10-01 18:14:24.221801 -0500 CDT}
	// {flow_id: 3, ip4, 100.10.20.8:2048 -> 100.10.20.3:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:14.398757 -0500 CDT, end: 2006-10-01 18:14:14.400133 -0500 CDT}
	// {flow_id: 10, ip4, 100.10.20.3:0 -> 100.10.20.12:0, proto: 1, count: 2, bytes: 148, payload_bytes: 64, start: 2006-10-01 18:14:58.196922 -0500 CDT, end: 2006-10-01 18:14:58.19762 -0500 CDT}
	// Processed 23 packets (1690 bytes) in 11 flows with 23 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_flow_icmp6EchoRequest() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/icmp6-echo-request.pcap")

	// CL options
	DebugPrintPackets = false
	DebugPrintFlows = true
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
	// {flow_id: 1, ip6, :::32768 -> ff02::1:0, proto: 58, count: 1, bytes: 62, payload_bytes: 0, start: 2008-11-26 14:06:11.994161 -0600 CST, end: 2008-11-26 14:06:11.994161 -0600 CST}
	// {flow_id: 2, ip6, ff02::1:33024 -> :::0, proto: 58, count: 1, bytes: 62, payload_bytes: 0, start: 2008-11-26 14:06:11.994421 -0600 CST, end: 2008-11-26 14:06:11.994421 -0600 CST}
	// Processed 2 packets (124 bytes) in 2 flows with 2 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_flow_tcpCompleteV4() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v4.pcap")

	// CL options
	DebugPrintPackets = false
	DebugPrintFlows = true
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
	// {flow_id: 2, ip4, 192.168.0.7:2111 -> 192.168.0.5:1449, proto: 6, count: 2, bytes: 122, payload_bytes: 0, start: 2009-04-27 16:00:04.084535 -0500 CDT, end: 2009-04-27 16:00:07.173944 -0500 CDT}
	// {flow_id: 1, ip4, 192.168.0.5:1449 -> 192.168.0.7:2111, proto: 6, count: 3, bytes: 170, payload_bytes: 0, start: 2009-04-27 16:00:04.066108 -0500 CDT, end: 2009-04-27 16:00:07.173911 -0500 CDT}
	// Processed 5 packets (292 bytes) in 2 flows with 5 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_flow_tcpCompleteV6() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v6.pcap")

	// CL options
	DebugPrintPackets = false
	DebugPrintFlows = true
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
	// {flow_id: 2, ip6, fe80::7:2111 -> fe80::5:1449, proto: 6, count: 2, bytes: 162, payload_bytes: 0, start: 2009-04-27 21:57:03.693061 -0500 CDT, end: 2009-04-27 21:57:03.6977 -0500 CDT}
	// {flow_id: 1, ip6, fe80::5:1449 -> fe80::7:2111, proto: 6, count: 3, bytes: 230, payload_bytes: 0, start: 2009-04-27 21:57:03.6915 -0500 CDT, end: 2009-04-27 21:57:03.696151 -0500 CDT}
	// Processed 5 packets (392 bytes) in 2 flows with 5 decoded, 0 errors, and 0 truncated.
}

func ExampleProcessPackets_flow_vlan() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/vlan.pcap")

	// CL options
	DebugPrintPackets = false
	DebugPrintFlows = true
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
	// {flow_id: 8, ip4, 131.151.104.96:137 -> 131.151.107.255:137, proto: 17, count: 3, bytes: 288, payload_bytes: 150, start: 1999-11-05 12:20:41.521798 -0600 CST, end: 1999-11-05 12:20:43.02384 -0600 CST}
	// {flow_id: 19, ip4, 131.151.115.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.375145 -0600 CST, end: 1999-11-05 12:20:43.375145 -0600 CST}
	// {flow_id: 16, ip4, 131.151.32.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.25041 -0600 CST, end: 1999-11-05 12:20:43.25041 -0600 CST}
	// {flow_id: 3, ip4, 131.151.5.55:138 -> 131.151.5.255:138, proto: 17, count: 1, bytes: 247, payload_bytes: 201, start: 1999-11-05 12:20:40.112031 -0600 CST, end: 1999-11-05 12:20:40.112031 -0600 CST}
	// {flow_id: 11, ip4, 131.151.6.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.08701 -0600 CST, end: 1999-11-05 12:20:43.08701 -0600 CST}
	// {flow_id: 6, ip4, 131.151.6.171:2048 -> 131.151.32.129:0, proto: 1, count: 5, bytes: 7575, payload_bytes: 7345, start: 1999-11-05 12:20:40.258261 -0600 CST, end: 1999-11-05 12:20:44.257898 -0600 CST}
	// {flow_id: 5, ip4, 131.151.32.129:1173 -> 131.151.32.21:6000, proto: 6, count: 27, bytes: 12918, payload_bytes: 11188, start: 1999-11-05 12:20:40.178702 -0600 CST, end: 1999-11-05 12:20:44.502622 -0600 CST}
	// {flow_id: 10, ip4, 131.151.5.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.079765 -0600 CST, end: 1999-11-05 12:20:43.079765 -0600 CST}
	// {flow_id: 4, ip4, 131.151.32.21:6000 -> 131.151.32.129:1173, proto: 6, count: 19, bytes: 2066, payload_bytes: 3584, start: 1999-11-05 12:20:40.16235 -0600 CST, end: 1999-11-05 12:20:44.501093 -0600 CST}
	// {flow_id: 2, ip4, 131.151.32.21:6000 -> 131.151.32.129:1162, proto: 6, count: 42, bytes: 9756, payload_bytes: 12312, start: 1999-11-05 12:20:40.064555 -0600 CST, end: 1999-11-05 12:20:44.130376 -0600 CST}
	// {flow_id: 13, ip4, 131.151.10.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.11533 -0600 CST, end: 1999-11-05 12:20:43.11533 -0600 CST}
	// {flow_id: 7, ip4, 131.151.32.129:0 -> 131.151.6.171:0, proto: 1, count: 5, bytes: 7575, payload_bytes: 7345, start: 1999-11-05 12:20:40.258417 -0600 CST, end: 1999-11-05 12:20:44.258042 -0600 CST}
	// {flow_id: 17, ip4, 131.151.107.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.363348 -0600 CST, end: 1999-11-05 12:20:43.363348 -0600 CST}
	// {flow_id: 14, ip4, 131.151.20.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.1705 -0600 CST, end: 1999-11-05 12:20:43.1705 -0600 CST}
	// {flow_id: 1, ip4, 131.151.32.129:1162 -> 131.151.32.21:6000, proto: 6, count: 96, bytes: 59948, payload_bytes: 55790, start: 1999-11-05 12:20:40.056226 -0600 CST, end: 1999-11-05 12:20:44.114318 -0600 CST}
	// {flow_id: 15, ip4, 131.151.32.79:138 -> 131.151.32.255:138, proto: 17, count: 1, bytes: 247, payload_bytes: 201, start: 1999-11-05 12:20:43.183825 -0600 CST, end: 1999-11-05 12:20:43.183825 -0600 CST}
	// {flow_id: 9, ip4, 131.151.32.71:138 -> 131.151.32.255:138, proto: 17, count: 1, bytes: 247, payload_bytes: 201, start: 1999-11-05 12:20:42.063074 -0600 CST, end: 1999-11-05 12:20:42.063074 -0600 CST}
	// {flow_id: 18, ip4, 131.151.111.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.36821 -0600 CST, end: 1999-11-05 12:20:43.36821 -0600 CST}
	// {flow_id: 12, ip4, 131.151.1.254:520 -> 255.255.255.255:520, proto: 17, count: 1, bytes: 70, payload_bytes: 24, start: 1999-11-05 12:20:43.09654 -0600 CST, end: 1999-11-05 12:20:43.09654 -0600 CST}
	// Processed 395 packets (101663 bytes) in 19 flows with 210 decoded, 185 errors, and 0 truncated.
}
