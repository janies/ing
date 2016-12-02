# Ing

[![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](http://opensource.org/licenses/MIT)

A network sensor that captures flow sessions and banners and stores them in
JSON files for network analysis.

The name _Ing_ is inspired by the Nordic rune
[Inguz](http://www.nordicrunes.info/ing.php).


## Dependencies

Install the following dependencies with `go get -u [package import path]`.

* [gopacket](https://github.com/google/gopacket)
* [lumberjack](https://github.com/natefinch/lumberjack) for rolling logs
* [ahocorasick](github.com/cloudflare/ahocorasick)
* libpcap and libpcap-devel


## Build and test

Run `make` to install dependencies and build the `ing` binary.  It will set
the `VERSION` and pass it and other identifying data to the `go build` command.
Unit and example tests are run with `make test` and benchmarking with
`make bench`.


## Build a service RPM

The [build-rpm](https://github.com/johnzachary/ing/tree/build-rpm) branch will
build an RPM that installs `ing` as a service.  Please see the branch for
installed binary, config, and service file details.


## Output files

Files are written to the `output` directory by default, but this is
configurable (see below).  Two types of JSON files are written: _flow_ and
_banners_.  Flow files are sessionized based on the standard
`{source IP, destination ip, source port, destination port, protocol}`
five-tuple and a VLAN tag (which may not be present).  Flows terminate if the
session ends "normally" with a `FIN` or `RST` flag for TCP sessions, if the
session hasn't seen a packet during an idle timeout period, or if the session
traffic exceeds an active timeout period.  Banners are extracted from the first
packet with a non-empty payload based on the terms in the
[etc/banner-terms.json](https://github.com/johnzachary/ing/blob/master/etc/banner-terms.json)
file.


## Usage
```
Usage: ./ing [OPTIONS] INPUT

INPUT: Packet source either as a PCAP file or a network device.
       If the latter, use the `--device` switch.

OPTIONS:
  -active-timeout uint
    	Active flow timeout in seconds (default 1800)
  -banner-terms string
    	Path to JSON file of banner terms (default "./banner-terms.json")
  -bpf string
    	Berkeley Packet Filter expression
  -debug-drop-output
    	Drop all output
  -debug-print-banners
    	Print Banners in short form
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
