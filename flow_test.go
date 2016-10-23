package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/gopacket/pcap"
)

// Testing

// Benchmarks

func BenchmarkFlows(b *testing.B) {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/allFileTypes.pcap")

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = false
	config.Debug.PrintErrors = false
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-allFileTypes"
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		defer close(done)
		wg.Add(3)
		inPackets := GeneratePackets(done, handle)
		inFlows := AssignFlows(done, inPackets)
		WriteFlows(done, inFlows)
		wg.Wait()
	}
	handle.Close()
	os.RemoveAll(config.OutputPrefix)
}

// Examples
func Example_flow_icmp() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/icmp.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-icmp"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(3)
	inPackets := GeneratePackets(done, handle)
	inFlows := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2006-10-01 23:14:09.03823 - 23:14:09.03964 (1.402ms)  ICMPv4 8:0 100.10.20.7 -> 100.10.20.3 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:20.28034 - 23:14:20.28175 (1.404ms)  ICMPv4 8:0 100.10.20.10 -> 100.10.20.3 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:24.22030 - 23:14:24.22165 (1.35ms)  ICMPv4 8:0 100.10.20.9 -> 100.10.20.3 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:09.03851 - 23:14:09.03972 (1.212ms)  ICMPv4 0:0 100.10.20.3 -> 100.10.20.7 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:58.19676 - 23:14:58.19741 (648µs)  ICMPv4 8:0 100.10.20.12 -> 100.10.20.3 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:20.28057 - 23:14:20.28200 (1.439ms)  ICMPv4 0:0 100.10.20.3 -> 100.10.20.10 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:24.22060 - 23:14:24.22180 (1.2ms)  ICMPv4 0:0 100.10.20.3 -> 100.10.20.9 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:58.19692 - 23:14:58.19762 (698µs)  ICMPv4 0:0 100.10.20.3 -> 100.10.20.12 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:19:09.05742 - 23:19:09.12164 (64.219ms)  ICMPv4 3:3 100.10.20.4 -> 100.20.1.3 (count: 3, bytes: 210, payload_bytes: 84)
	// 2006-10-01 23:14:14.39899 - 23:14:14.40043 (1.439ms)  ICMPv4 0:0 100.10.20.3 -> 100.10.20.8 (count: 2, bytes: 148, payload_bytes: 64)
	// 2006-10-01 23:14:14.39875 - 23:14:14.40013 (1.376ms)  ICMPv4 8:0 100.10.20.8 -> 100.10.20.3 (count: 2, bytes: 148, payload_bytes: 64)
	// Processed 23 packets (1690 bytes) in 11 flows with 23 decoded, and 0 truncated.
}

func Example_flow_icmp6EchoRequest() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/icmp6-echo-request.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-icmp6-echo-request"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(3)
	inPackets := GeneratePackets(done, handle)
	inFlows := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2008-11-26 20:06:11.99416 - 20:06:11.99416 (0s)  ICMPv6 128:0 :: -> ff02::1 (count: 1, bytes: 62, payload_bytes: 0)
	// 2008-11-26 20:06:11.99442 - 20:06:11.99442 (0s)  ICMPv6 129:0 ff02::1 -> :: (count: 1, bytes: 62, payload_bytes: 0)
	// Processed 2 packets (124 bytes) in 2 flows with 2 decoded, and 0 truncated.
}

func Example_flow_tcpCompleteV4() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v4.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-tcp-complete-v4"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(3)
	inPackets := GeneratePackets(done, handle)
	inFlows := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2009-04-27 21:00:04.06610 - 21:00:07.17391 (3.107803s) TCP 192.168.0.5:1449 -> 192.168.0.7:2111 (count: 3, bytes: 170, payload_bytes: 0)
	// 2009-04-27 21:00:04.08453 - 21:00:07.17394 (3.089409s) TCP 192.168.0.7:2111 -> 192.168.0.5:1449 (count: 2, bytes: 122, payload_bytes: 0)
	// Processed 5 packets (292 bytes) in 2 flows with 5 decoded, and 0 truncated.
}

func Example_flow_tcpCompleteV6() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/tcp-complete-v6.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-tcp-complete-v6"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(3)
	inPackets := GeneratePackets(done, handle)
	inFlows := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2009-04-28 02:57:03.69150 - 02:57:03.69615 (4.651ms) TCP fe80::5.1449 -> fe80::7.2111 (count: 3, bytes: 230, payload_bytes: 0)
	// 2009-04-28 02:57:03.69306 - 02:57:03.69770 (4.639ms) TCP fe80::7.2111 -> fe80::5.1449 (count: 2, bytes: 162, payload_bytes: 0)
	// Processed 5 packets (392 bytes) in 2 flows with 5 decoded, and 0 truncated.
}

func Example_flow_vlan() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/vlan.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-vlan"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(3)
	inPackets := GeneratePackets(done, handle)
	inFlows := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 1999-11-05 18:20:43.37514 - 18:20:43.37514 (0s) UDP 131.151.115.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:40.05622 - 18:20:44.11431 (4.058092s) TCP 131.151.32.129:1162 -> 131.151.32.21:6000 (count: 96, bytes: 59948, payload_bytes: 53228)
	// 1999-11-05 18:20:43.25041 - 18:20:43.25041 (0s) UDP 131.151.32.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:43.09654 - 18:20:43.09654 (0s) UDP 131.151.1.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:43.17050 - 18:20:43.17050 (0s) UDP 131.151.20.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:40.25841 - 18:20:44.25804 (3.999625s)  ICMPv4 0:0 131.151.32.129 -> 131.151.6.171 (count: 5, bytes: 7575, payload_bytes: 7345)
	// 1999-11-05 18:20:43.07976 - 18:20:43.07976 (0s) UDP 131.151.5.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:43.36821 - 18:20:43.36821 (0s) UDP 131.151.111.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:43.08701 - 18:20:43.08701 (0s) UDP 131.151.6.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:40.25826 - 18:20:44.25789 (3.999637s)  ICMPv4 8:0 131.151.6.171 -> 131.151.32.129 (count: 5, bytes: 7575, payload_bytes: 7345)
	// 1999-11-05 18:20:41.52179 - 18:20:43.02384 (1.502042s) UDP 131.151.104.96:137 -> 131.151.107.255:137 (count: 3, bytes: 288, payload_bytes: 150)
	// 1999-11-05 18:20:40.17870 - 18:20:44.50262 (4.32392s) TCP 131.151.32.129:1173 -> 131.151.32.21:6000 (count: 27, bytes: 12918, payload_bytes: 11028)
	// 1999-11-05 18:20:42.06307 - 18:20:42.06307 (0s) UDP 131.151.32.71:138 -> 131.151.32.255:138 (count: 1, bytes: 247, payload_bytes: 201)
	// 1999-11-05 18:20:40.06455 - 18:20:44.13037 (4.065821s) TCP 131.151.32.21:6000 -> 131.151.32.129:1162 (count: 42, bytes: 9756, payload_bytes: 6816)
	// 1999-11-05 18:20:40.16235 - 18:20:44.50109 (4.338743s) TCP 131.151.32.21:6000 -> 131.151.32.129:1173 (count: 19, bytes: 2066, payload_bytes: 736)
	// 1999-11-05 18:20:43.18382 - 18:20:43.18382 (0s) UDP 131.151.32.79:138 -> 131.151.32.255:138 (count: 1, bytes: 247, payload_bytes: 201)
	// 1999-11-05 18:20:43.11533 - 18:20:43.11533 (0s) UDP 131.151.10.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:43.36334 - 18:20:43.36334 (0s) UDP 131.151.107.254:520 -> 255.255.255.255:520 (count: 1, bytes: 70, payload_bytes: 24)
	// 1999-11-05 18:20:40.11203 - 18:20:40.11203 (0s) UDP 131.151.5.55:138 -> 131.151.5.255:138 (count: 1, bytes: 247, payload_bytes: 201)
	// Processed 395 packets (101663 bytes) in 19 flows with 210 decoded, and 0 truncated.
}
