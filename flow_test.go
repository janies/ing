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
	handle, _ = pcap.OpenOffline("testdata/vlan.pcap")

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = false
	config.Debug.PrintErrors = false
	config.Debug.PrintBanners = false
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
		inFlows, _ := AssignFlows(done, inPackets)
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
	inFlows, _ := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2011-06-27 03:21:27.02426 - 03:21:30.02660 (3.002342s)  ICMPv4 8:0 192.168.0.89 -> 192.168.0.1 (count: 8, bytes: 592, payload_bytes: 256)
	// 2011-06-27 03:21:27.02817 - 03:21:30.03047 (3.002296s)  ICMPv4 0:0 192.168.0.1 -> 192.168.0.89 (count: 4, bytes: 296, payload_bytes: 128)
	// Processed 12 packets (888 bytes) in 2 flows with 12 decoded, and 0 truncated.
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
	inFlows, _ := AssignFlows(done, inPackets)
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
	inFlows, _ := AssignFlows(done, inPackets)
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

func Example_flow_udpV4() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/udp-v4.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.SnapLen = 65536
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-udp-v4"

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
	inFlows, _ := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2009-04-07 14:57:26.36958 - 14:57:26.36958 (0s) UDP 192.168.0.6:1393 -> 199.45.32.43:53 (count: 1, bytes: 85, payload_bytes: 32)
	// 2009-04-07 14:57:26.38144 - 14:57:26.38144 (0s) UDP 199.45.32.43:53 -> 192.168.0.6:1393 (count: 1, bytes: 121, payload_bytes: 32)
	// 2009-04-07 14:57:26.38343 - 14:57:26.38343 (0s) UDP 192.168.0.6:1394 -> 199.45.32.43:53 (count: 1, bytes: 72, payload_bytes: 32)
	// 2009-04-07 14:57:26.39546 - 14:57:26.39546 (0s) UDP 199.45.32.43:53 -> 192.168.0.6:1394 (count: 1, bytes: 88, payload_bytes: 32)
	// 2009-04-27 21:29:55.99037 - 21:29:55.99037 (0s) UDP 192.168.0.5:1026 -> 83.170.6.76:3544 (count: 1, bytes: 119, payload_bytes: 77)
	// 2009-04-27 21:29:56.10216 - 21:29:56.10216 (0s) UDP 83.170.6.76:3544 -> 192.168.0.5:1026 (count: 1, bytes: 159, payload_bytes: 117)
	// 2009-04-27 21:33:37.88300 - 21:33:37.88300 (0s) UDP 192.168.0.5:1465 -> 199.45.32.43:53 (count: 1, bytes: 74, payload_bytes: 117)
	// 2009-04-27 21:33:37.89556 - 21:33:37.89556 (0s) UDP 199.45.32.43:53 -> 192.168.0.5:1465 (count: 1, bytes: 142, payload_bytes: 117)
	// 2009-04-27 21:37:26.03775 - 21:37:26.03775 (0s) UDP 192.168.0.7:35393 -> 199.45.32.43:53 (count: 1, bytes: 72, payload_bytes: 117)
	// 2009-04-27 21:37:26.05036 - 21:37:26.05036 (0s) UDP 199.45.32.43:53 -> 192.168.0.7:35393 (count: 1, bytes: 100, payload_bytes: 117)
	// 2009-04-27 21:37:50.77412 - 21:37:50.77412 (0s) UDP 192.168.0.7:33912 -> 203.178.141.194:53 (count: 1, bytes: 72, payload_bytes: 117)
	// 2009-04-27 21:37:50.97514 - 21:37:50.97514 (0s) UDP 203.178.141.194:53 -> 192.168.0.7:33912 (count: 1, bytes: 295, payload_bytes: 117)
	// 2009-04-27 21:39:56.52384 - 21:39:56.52384 (0s) UDP 192.168.0.7:41008 -> 199.45.32.43:53 (count: 1, bytes: 132, payload_bytes: 117)
	// 2009-04-27 21:39:56.92310 - 21:39:56.92310 (0s) UDP 199.45.32.43:53 -> 192.168.0.7:41008 (count: 1, bytes: 161, payload_bytes: 117)
	// 2009-04-27 21:40:53.51539 - 21:40:53.51539 (0s) UDP 192.168.0.7:37308 -> 199.45.32.43:53 (count: 1, bytes: 84, payload_bytes: 117)
	// 2009-04-27 21:40:53.52835 - 21:40:53.52835 (0s) UDP 199.45.32.43:53 -> 192.168.0.7:37308 (count: 1, bytes: 138, payload_bytes: 117)
	// 2009-04-27 21:47:08.64744 - 21:47:08.64744 (0s) UDP 192.168.0.7:56309 -> 199.45.32.43:53 (count: 1, bytes: 70, payload_bytes: 117)
	// 2009-04-27 21:47:08.65843 - 21:47:08.65843 (0s) UDP 199.45.32.43:53 -> 192.168.0.7:56309 (count: 1, bytes: 206, payload_bytes: 117)
	// 2009-04-27 21:47:17.52596 - 21:47:17.52596 (0s) UDP 192.168.0.7:45558 -> 199.45.32.43:53 (count: 1, bytes: 70, payload_bytes: 117)
	// 2009-04-27 21:47:17.53708 - 21:47:17.53708 (0s) UDP 199.45.32.43:53 -> 192.168.0.7:45558 (count: 1, bytes: 206, payload_bytes: 117)
	// 2009-04-29 18:42:33.45696 - 18:42:33.45696 (0s) UDP 192.168.0.7:56305 -> 199.45.32.43:53 (count: 1, bytes: 75, payload_bytes: 117)
	// 2009-04-29 18:42:33.47450 - 18:42:33.47450 (0s) UDP 199.45.32.43:53 -> 192.168.0.7:56305 (count: 1, bytes: 112, payload_bytes: 117)
	// 2009-04-29 18:44:36.04307 - 18:44:36.04307 (0s) UDP 192.168.0.7:53983 -> 199.45.32.43:53 (count: 1, bytes: 87, payload_bytes: 117)
	// 2009-04-29 18:44:36.05559 - 18:44:36.05559 (0s) UDP 199.45.32.43:53 -> 192.168.0.7:53983 (count: 1, bytes: 311, payload_bytes: 117)
	// Processed 24 packets (3051 bytes) in 24 flows with 24 decoded, and 0 truncated.
}

func Example_flow_udpV6() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/udp-v6.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-udp-v6"

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
	inFlows, _ := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2009-04-28 02:57:03.47668 - 02:57:03.47668 (0s) UDP fe80::5.1026 -> fe80::76.3544 (count: 1, bytes: 139, payload_bytes: 77)
	// 2009-04-28 02:57:03.48219 - 02:57:03.48219 (0s) UDP fe80::76.3544 -> fe80::5.1026 (count: 1, bytes: 179, payload_bytes: 117)
	// 2009-04-28 02:57:03.64097 - 02:57:03.64097 (0s) UDP fe80::7.35393 -> fe80::43.53 (count: 1, bytes: 92, payload_bytes: 117)
	// 2009-04-28 02:57:03.64317 - 02:57:03.64317 (0s) UDP fe80::43.53 -> fe80::7.35393 (count: 1, bytes: 132, payload_bytes: 117)
	// 2009-04-28 02:57:03.65489 - 02:57:03.65489 (0s) UDP fe80::7.41008 -> fe80::43.53 (count: 1, bytes: 152, payload_bytes: 117)
	// 2009-04-28 02:57:03.67070 - 02:57:03.67070 (0s) UDP fe80::7.56309 -> fe80::43.53 (count: 1, bytes: 90, payload_bytes: 117)
	// 2009-04-28 02:57:03.67286 - 02:57:03.67286 (0s) UDP fe80::43.53 -> fe80::7.56309 (count: 1, bytes: 362, payload_bytes: 117)
	// 2009-04-28 02:57:04.15066 - 02:57:04.15066 (0s) UDP fe80::7.45558 -> fe80::43.53 (count: 1, bytes: 90, payload_bytes: 117)
	// 2009-04-28 02:57:04.15282 - 02:57:04.15282 (0s) UDP fe80::43.53 -> fe80::7.45558 (count: 1, bytes: 314, payload_bytes: 117)
	// 2009-04-28 02:57:04.22950 - 02:57:04.22950 (0s) UDP fe80::7.33912 -> fe80::194.53 (count: 1, bytes: 92, payload_bytes: 117)
	// 2009-04-28 02:57:04.23171 - 02:57:04.23171 (0s) UDP fe80::194.53 -> fe80::7.33912 (count: 1, bytes: 444, payload_bytes: 117)
	// 2009-04-28 02:57:04.37197 - 02:57:04.37197 (0s) UDP fe80::5.1465 -> fe80::43.53 (count: 1, bytes: 94, payload_bytes: 117)
	// 2009-04-28 02:57:04.37414 - 02:57:04.37414 (0s) UDP fe80::43.53 -> fe80::5.1465 (count: 1, bytes: 234, payload_bytes: 117)
	// 2009-04-28 02:57:04.38861 - 02:57:04.38861 (0s) UDP fe80::7.37308 -> fe80::43.53 (count: 1, bytes: 104, payload_bytes: 117)
	// 2009-04-29 18:46:45.56711 - 18:46:45.56711 (0s) UDP fe80::7.53983 -> fe80::43.53 (count: 1, bytes: 107, payload_bytes: 117)
	// 2009-04-29 18:46:45.56939 - 18:46:45.56939 (0s) UDP fe80::43.53 -> fe80::7.53983 (count: 1, bytes: 466, payload_bytes: 117)
	// 2009-04-29 18:46:45.59107 - 18:46:45.59107 (0s) UDP fe80::7.56305 -> fe80::43.53 (count: 1, bytes: 95, payload_bytes: 117)
	// 2009-04-29 18:46:45.59340 - 18:46:45.59340 (0s) UDP fe80::43.53 -> fe80::7.56305 (count: 1, bytes: 174, payload_bytes: 117)
	// Processed 20 packets (3360 bytes) in 18 flows with 18 decoded, and 0 truncated.
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
	inFlows, _ := AssignFlows(done, inPackets)
	WriteFlows(done, inFlows)
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2012-07-18 20:10:04.13527 - 20:10:24.64204 (20.506772s) TCP 10.0.0.6:8080 -> 10.0.0.9:60351 (count: 3, bytes: 882, payload_bytes: 694)
	// 2012-07-18 20:10:04.13503 - 20:10:24.64206 (20.507033s) TCP 10.0.0.6:8080 -> 10.0.0.9:60350 (count: 3, bytes: 853, payload_bytes: 665)
	// 2012-07-18 20:10:00.75156 - 20:10:24.64295 (23.891393s) TCP 10.0.0.6:8080 -> 10.0.0.9:60338 (count: 37, bytes: 49153, payload_bytes: 46993)
	// 2012-07-18 20:10:04.13373 - 20:10:24.64395 (20.510219s) TCP 10.0.0.6:8080 -> 10.0.0.9:60345 (count: 6, bytes: 3862, payload_bytes: 3500)
	// 2012-07-18 20:10:04.13524 - 20:10:25.85302 (21.717783s) TCP 10.0.0.9:60351 -> 10.0.0.6:8080 (count: 6, bytes: 887, payload_bytes: 503)
	// 2012-07-18 20:10:04.13498 - 20:10:25.85319 (21.718211s) TCP 10.0.0.9:60350 -> 10.0.0.6:8080 (count: 6, bytes: 887, payload_bytes: 503)
	// 2012-07-18 20:10:00.75135 - 20:10:25.85347 (25.10212s) TCP 10.0.0.9:60338 -> 10.0.0.6:8080 (count: 27, bytes: 4144, payload_bytes: 2440)
	// 2012-07-18 20:10:04.13373 - 20:10:25.85347 (21.719742s) TCP 10.0.0.9:60345 -> 10.0.0.6:8080 (count: 8, bytes: 1510, payload_bytes: 1004)
	// 2012-07-18 20:10:04.13336 - 20:10:27.09114 (22.957783s) TCP 10.0.0.6:8080 -> 10.0.0.9:60344 (count: 6, bytes: 4619, payload_bytes: 4257)
	// 2012-07-18 20:10:04.13429 - 20:10:28.20415 (24.069862s) TCP 10.0.0.6:8080 -> 10.0.0.9:60346 (count: 7, bytes: 5196, payload_bytes: 4776)
	// 2012-07-18 20:10:04.13498 - 20:10:28.86319 (24.728207s) TCP 10.0.0.6:8080 -> 10.0.0.9:60348 (count: 7, bytes: 5091, payload_bytes: 4671)
	// 2012-07-18 20:10:04.13442 - 20:10:30.13332 (25.998905s) TCP 10.0.0.6:8080 -> 10.0.0.9:60347 (count: 7, bytes: 6277, payload_bytes: 5857)
	// 2012-07-18 20:10:04.13498 - 20:10:30.14838 (26.013401s) TCP 10.0.0.6:8080 -> 10.0.0.9:60349 (count: 8, bytes: 7344, payload_bytes: 6866)
	// 2012-07-18 20:09:56.03580 - 20:10:31.34934 (35.313539s) TCP 10.0.0.6:8080 -> 10.0.0.9:60335 (count: 31, bytes: 39803, payload_bytes: 37991)
	// 2012-07-18 20:10:04.13334 - 20:10:35.85314 (31.7198s) TCP 10.0.0.9:60344 -> 10.0.0.6:8080 (count: 9, bytes: 1750, payload_bytes: 1180)
	// 2012-07-18 20:10:04.13429 - 20:10:35.85334 (31.71905s) TCP 10.0.0.9:60346 -> 10.0.0.6:8080 (count: 10, bytes: 1845, payload_bytes: 1205)
	// 2012-07-18 20:10:04.13498 - 20:10:35.85349 (31.718512s) TCP 10.0.0.9:60348 -> 10.0.0.6:8080 (count: 10, bytes: 1783, payload_bytes: 1143)
	// 2012-07-18 20:10:04.13441 - 20:10:35.85374 (31.719329s) TCP 10.0.0.9:60347 -> 10.0.0.6:8080 (count: 9, bytes: 1826, payload_bytes: 1256)
	// 2012-07-18 20:10:04.13498 - 20:10:35.85389 (31.71891s) TCP 10.0.0.9:60349 -> 10.0.0.6:8080 (count: 10, bytes: 1642, payload_bytes: 1008)
	// 2012-07-18 20:09:56.03576 - 20:10:35.85404 (39.818285s) TCP 10.0.0.9:60335 -> 10.0.0.6:8080 (count: 27, bytes: 5091, payload_bytes: 3399)
	// 2012-07-18 20:09:51.25377 - 20:09:51.25377 (0s) TCP 10.0.0.9:60285 -> 10.0.0.6:8080 (count: 1, bytes: 64, payload_bytes: 0)
	// 2012-07-18 20:09:51.25377 - 20:09:51.25377 (0s) TCP 10.0.0.6:8080 -> 10.0.0.9:60285 (count: 1, bytes: 60, payload_bytes: 0)
	// Processed 239 packets (144569 bytes) in 22 flows with 239 decoded, and 0 truncated.
}
