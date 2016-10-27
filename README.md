# Ing

A packet processor and metadata collector for industrial control system (ISC) and healthcare
networks.

## Dependencies

* [gopacket](https://github.com/google/gopacket) (`go get github.com/google/gopacket`)
* [lumberjack](https://github.com/natefinch/lumberjack) for rolling logs
* libpcap and libpcap-devel


## Build

The file `$ROOT/build.sh` is the build script for Ing.  It will set the `VERSION` and pass it and
other identifying data to the `go build` command.

## Usage
```
Usage: ./ing [OPTIONS] INPUT

INPUT: Packet source either as a PCAP file or a network device.
       If the latter, use the `--device` switch.

OPTIONS:
  -active-timeout uint
    	Active flow timeout in seconds (default 1800)
  -bpf string
    	Berkeley Packet Filter expression
  -debug-drop-flows
    	Don't write flows to files
  -debug-print-errors
    	Print errors
  -debug-print-flows
    	Print flows in short form
  -debug-print-packets
    	Print packets in short form
  -device
    	INPUT is a live network device
  -filter-small-flows
    	Don't output TCP flows with 1-3 packets
  -filter-tcp-flags
    	Drop and report suspicious TCP flag combinations
  -idle-timeout uint
    	Idle flow timout in seconds (default 300)
  -output-interval uint
    	Output rotation interval in minutes (default 10)
  -output-prefix string
    	Path to output files (default "./output/")
  -output-slug string
    	Output file slug (default "-ing")
  -snaplen int
    	Read snaplen bytes from each packet (default 65536)
  -version
    	Show version information and exit
```
