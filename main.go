// This source code is covered by the license found in the LICENSE file.
//
// Ing is a packet processor and metadata collector based on gopacket.  It reads packets from a
// PCAP file or a live network device.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

// Build variables
var (
	Version   string // Version number of application
	BuildTime string // Application build time
	GitHash   string // Current git branch from which the applicatoin was built
)

// Config groups global configuration values.
var config struct {
	ActiveTimeout          uint   // Duration in seconds for active flow terminations
	IdleTimeout            uint   // Duration in seconds for terminating inactive flows
	IdlePacketDuration     int    // Number of packets to skip before checking for idle timeouts
	OutputPrefix           string // Path to output files
	OutputRotationInterval uint   // Rotational interval for output files
	OutputSlug             string // Slug for output files
	PcapTimeout            int    // Configures the pcap handler for packet buffering in milliseconds
	SnapLen                int    // Number of packet bytes to capture
	FilterTCPFlags         bool   // Drop and report packets with abnormal TCP flag combinations
	FilterSmallFlows       bool   // Filter out small TCP flows with 1-3 packets
	BannerTermsFile        string // File containing banner search terms
	Debug                  struct {
		DropOutput   bool // Drop all output; useful for performance profiling
		PrintBanners bool // Print every banner in short form
		PrintErrors  bool // Print errors
		PrintFlows   bool // Print every flow in short form
		PrintPackets bool // Print every packet in short form
	}
}

var wg sync.WaitGroup

func main() {
	var packetHandle *pcap.Handle
	var err error

	// Since these flags are local to this function, i.e. setting up a PCAP handle, we don't need
	// them as global configuration variables.
	bpf := flag.String("bpf", "", "Berkeley Packet Filter expression")
	isDevice := flag.Bool("device", false, "INPUT is a live network device")
	showVersion := flag.Bool("version", false, "Show version information and exit")
	config.PcapTimeout = 10

	// These are global configuration variables, so we need to call XyzVar().
	flag.UintVar(&config.ActiveTimeout, "active-timeout", 1800, "Active flow timeout in seconds")
	flag.UintVar(&config.IdleTimeout, "idle-timeout", 300, "Idle flow timout in seconds")
	flag.StringVar(&config.OutputPrefix, "output-prefix", "./output/", "Path to output files")
	flag.UintVar(&config.OutputRotationInterval, "output-interval", 10, "Output rotation interval in minutes")
	flag.StringVar(&config.OutputSlug, "output-slug", "-ing", "Output file slug")
	flag.IntVar(&config.SnapLen, "snaplen", 65536, "Read snaplen bytes from each packet")
	flag.BoolVar(&config.FilterTCPFlags, "filter-tcp-flags", false, "Drop and report suspicious TCP flag combinations")
	flag.BoolVar(&config.FilterSmallFlows, "filter-small-flows", false, "Don't output TCP flows with 1-3 packets")
	flag.StringVar(&config.BannerTermsFile, "banner-terms", "./banner-terms.json", "Path to JSON file of banner terms")
	flag.BoolVar(&config.Debug.DropOutput, "debug-drop-output", false, "Drop all output")
	flag.BoolVar(&config.Debug.PrintBanners, "debug-print-banners", false, "Print Banners in short form")
	flag.BoolVar(&config.Debug.PrintErrors, "debug-print-errors", false, "Print errors")
	flag.BoolVar(&config.Debug.PrintFlows, "debug-print-flows", false, "Print flows in short form")
	flag.BoolVar(&config.Debug.PrintPackets, "debug-print-packets", false, "Print packets in short form")

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
		fmt.Println(os.Args[0], "version", Version)
		fmt.Println("Build timestamp:", BuildTime)
		fmt.Println("Git commit:", GitHash)
		os.Exit(0)
	}

	if len(args) < 1 {
		fmt.Println("Please provide a packet source.")
		os.Exit(1)
	}

	if *isDevice {
		packetHandle, err = pcap.OpenLive(args[0], int32(config.SnapLen), true,
			time.Duration(config.PcapTimeout))
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

	// Set up the workflow to collect flows and banners
	done := make(chan struct{})
	defer close(done)
	wg.Add(5) // NOTE: number of computations that have goroutines; ensure they call wg.Done()
	inPackets := GeneratePackets(done, packetHandle)
	inFlows, inPayloads := AssignFlows(done, inPackets)
	inBanners := ExtractBanners(done, inPayloads)
	if config.Debug.DropOutput {
		DropFlows(done, inFlows)
		DropBanners(done, inBanners)
	} else {
		WriteFlows(done, inFlows)
		WriteBanners(done, inBanners)
	}
	wg.Wait()
	fmt.Printf("Processed %v packets (%v bytes) in %v flows with %v decoded, and %v truncated.\n",
		stats.TotalPackets, stats.NumBytes, stats.TotalFlows, stats.NumDecoded, stats.NumTruncated)
	// done will be closed by the deferred call.
}
