package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket/pcap"
)

// Testing

// Benchmarks

// Examples
func Example_banner_gnutellaStream() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/gnutella_stream.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = false
	config.Debug.PrintBanners = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-test"
	config.BannerTermsFile = "etc/banner-terms.json"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(5) // NOTE: number of computations that have goroutines; ensure they call wg.Done()
	inPackets := GeneratePackets(done, handle)
	inFlows, inPayloads := AssignFlows(done, inPackets)
	inBanners := ExtractBanners(done, inPayloads)
	WriteFlows(done, inFlows)
	WriteBanners(done, inBanners)
	wg.Wait()

	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2008-06-06 11:19:14.43268, ip: 10.60.50.76, flow_id: 1, tag: gnutella-svc/6346, type: client, banner: GNUTELLA CONNECT/0.6
	// 2008-06-06 11:19:14.43268, ip: 10.60.50.76, flow_id: 1, tag: www-http/80, type: client, banner: gtk-gnutella/0.96.4-14059 (2007-07-07; GTK2; FreeBSD i386)
	// 2008-06-06 11:19:14.43917, ip: 10.60.50.76, flow_id: 2, tag: gnutella-svc/6346, type: client, banner: GNUTELLA CONNECT/0.6
	// 2008-06-06 11:19:14.43917, ip: 10.60.50.76, flow_id: 2, tag: www-http/80, type: client, banner: gtk-gnutella/0.96.4-14059 (2007-07-07; GTK2; FreeBSD i386)
	// 2008-06-06 11:19:14.43923, ip: 10.60.50.76, flow_id: 3, tag: gnutella-svc/6346, type: client, banner: GNUTELLA CONNECT/0.6
	// 2008-06-06 11:19:14.43923, ip: 10.60.50.76, flow_id: 3, tag: www-http/80, type: client, banner: gtk-gnutella/0.96.4-14059 (2007-07-07; GTK2; FreeBSD i386)
	// 2008-06-06 11:19:14.69888, ip: 68.195.186.169, flow_id: 4, tag: gnutella-svc/6346, type: client, banner: GNUTELLA/0.6 503 We're Leaves
	// 2008-06-06 11:19:14.69926, ip: 69.117.16.255, flow_id: 5, tag: gnutella-svc/6346, type: client, banner: GNUTELLA/0.6 200 OK
	// 2008-06-06 11:19:14.83473, ip: 69.115.123.214, flow_id: 6, tag: gnutella-svc/6346, type: client, banner: GNUTELLA/0.6 503 No Leaf Slots
	// Processed 7 packets (3052 bytes) in 6 flows with 7 decoded, and 0 truncated.
}

func Example_flow_httpV4() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/http-v4.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = false
	config.Debug.PrintBanners = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-test"
	config.BannerTermsFile = "etc/banner-terms.json"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(5) // NOTE: number of computations that have goroutines; ensure they call wg.Done()
	inPackets := GeneratePackets(done, handle)
	inFlows, inPayloads := AssignFlows(done, inPackets)
	inBanners := ExtractBanners(done, inPayloads)
	WriteFlows(done, inFlows)
	WriteBanners(done, inBanners)
	wg.Wait()

	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2009-04-07 14:52:16.42835, ip: 192.168.0.6, flow_id: 1, tag: www-http/80, type: client, banner: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8 (.NET CLR 3.5.30729)
	// 2009-04-07 14:52:16.49512, ip: 216.34.181.45, flow_id: 2, tag: www-http/80, type: server, banner: Apache/1.3.41 (Unix) mod_perl/1.31-rc4
	// 2009-04-27 22:02:08.27435, ip: 192.168.0.5, flow_id: 3, tag: www-http/80, type: client, banner: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.59 Safari/525.19
	// Processed 31 packets (18983 bytes) in 4 flows with 31 decoded, and 0 truncated.
}

func Example_flow_msSMTP() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/ms-smtp.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = false
	config.Debug.PrintBanners = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-test"
	config.BannerTermsFile = "etc/banner-terms.json"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(5) // NOTE: number of computations that have goroutines; ensure they call wg.Done()
	inPackets := GeneratePackets(done, handle)
	inFlows, inPayloads := AssignFlows(done, inPackets)
	inBanners := ExtractBanners(done, inPayloads)
	WriteFlows(done, inFlows)
	WriteBanners(done, inBanners)
	wg.Wait()

	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2006-02-04 00:40:54.25383, ip: 192.168.26.130, flow_id: 2, tag: smtp/25, type: server, banner: exchdc1.dotnetzone.com ESMTP Server (Microsoft Exchange Internet Mail Service 5.5.2448.0
	// 2006-02-04 00:40:59.95286, ip: 192.168.26.130, flow_id: 5, tag: smtp/25, type: server, banner: exchdc1.dotnetzone.com ESMTP Server (Microsoft Exchange Internet Mail Service 5.5.2448.0
	// Processed 39 packets (4209 bytes) in 5 flows with 39 decoded, and 0 truncated.
}

func Example_flow_sshSessionV4() {
	var handle *pcap.Handle
	handle, _ = pcap.OpenOffline("testdata/ssh-session-v4.pcap")
	defer handle.Close()

	// CL options
	config.Debug.PrintPackets = false
	config.Debug.PrintFlows = false
	config.Debug.PrintBanners = true
	config.ActiveTimeout = 1800
	config.IdleTimeout = 300
	config.OutputPrefix = "/tmp/ing/output/"
	config.OutputRotationInterval = 5
	config.OutputSlug = "-test"
	config.BannerTermsFile = "etc/banner-terms.json"

	// State
	stats.NumBytes = 0
	stats.NumDecoded = 0
	stats.NumTruncated = 0
	stats.TotalPackets = 0
	stats.TotalFlows = 0

	done := make(chan struct{})
	defer close(done)
	wg.Add(5) // NOTE: number of computations that have goroutines; ensure they call wg.Done()
	inPackets := GeneratePackets(done, handle)
	inFlows, inPayloads := AssignFlows(done, inPackets)
	inBanners := ExtractBanners(done, inPayloads)
	WriteFlows(done, inFlows)
	WriteBanners(done, inBanners)
	wg.Wait()

	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	os.RemoveAll(config.OutputPrefix)
	// Output:
	// 2009-04-27 21:48:32.87955, ip: 192.168.0.7, flow_id: 2, tag: ssh/22, type: server, banner: SSH-2.0-OpenSSH_5.1
	// 2009-04-27 21:48:32.92382, ip: 192.168.0.5, flow_id: 1, tag: ssh/22, type: client, banner: SSH-2.0-PuTTY_Release_0.60
	// Processed 23 packets (4933 bytes) in 3 flows with 23 decoded, and 0 truncated.
}
