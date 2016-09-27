# Ing

[![GoReportCard](http://goreportcard.com/badge/elastic/beats)](http://goreportcard.com/report/elastic/beats)

A packet processor and metadata collected for industrial control system (ISC) networks.

## Dependencies

* [gopacket](https://github.com/google/gopacket) (`go get github.com/google/gopacket`)
* libpcap


## Build

The file `$ROOT/build.sh` is the build script for Ing.  It will set the `VERSION` and pass it and
other identifying data to the `go build` command.

## Usage
```
Usage: ./ing [OPTIONS] INPUT

INPUT: Packet source either as a PCAP file or a network device.
       If the latter, use the `--device` switch.

OPTIONS:
  -bpf string
        Berkeley Packet Filter expression
  -device
        INPUT is a live network device
  -snaplen int
        Read snaplen bytes from each packet (default 65536)
  -version
        Show version information and exit
```
