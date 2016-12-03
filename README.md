# Ing

[![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](http://opensource.org/licenses/MIT)

A network sensor that captures flow sessions and banners and stores them in
JSON files for network analysis.

The name _Ing_ is inspired by the Nordic rune [Inguz](http://www.nordicrunes.info/ing.php).


## Usage

### Golang package dependencies
* [gopacket](https://github.com/google/gopacket) for packet parsing
* [lumberjack](https://github.com/natefinch/lumberjack) for rolling logs
* [ahocorasick](github.com/cloudflare/ahocorasick) for banner searching in payloads

### Installation

1. Install [golang](https://golang.org/doc/install).  Version 1.7 or greater is suggested.

2. Install [libpcap](http://www.tcpdump.org/), including the development headers.

3. Run `make` to install golang package dependencies and build the `ing` binary.
 
4. Copy the `ing` binary and `etc/banner-terms.json` files anywhere you like.


### Testing
Unit and example tests are run with `make test` and benchmarking with `make bench`.


### Building a service RPM
The [build-rpm](https://github.com/johnzachary/ing/tree/build-rpm) branch will
build an RPM that installs `ing` as a service.  Please see the branch for
installed binary, config, and service file details.


### Running Ing

`ing` is a simple program to use.  It supports reading packets from a PCAP file
or from a live network device.  To get started, you can run `ing` on one of the
test PCAP files in the following way:

```
$ ing --banner-terms=etc/banner-terms.json testdata/holiday-card.pcap
Processed 48 packets (64944 bytes) in 4 flows with 48 decoded, and 0 truncated.
```

Output files are written to the `output` directory by default. There are two files
in this directory. One is a file with four flow records and the other is a file with
two banner records.  Files are output by default on a rolling basis every 10 minutes
or up to a maximum size of 100 MB. If you run `ing` on live network device over an
extended period, old files will be removed every 24 hours.

`ing` will terminate gracefully on a `Ctrl-C` command, and it supports the following
command line options:

```
Usage: ing [OPTIONS] INPUT

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


## Output files

Files are written to the `output` directory by default, but this is configurable
with the `--output-prefix` option.  `ing` generates two types of JSON files: _flow_
and _banner_.  

### Flow files

Packets are sessionized into flows based on the standard
`[source IP, destination ip, source port, destination port, protocol]`
five-tuple and a VLAN tag (which may not be present).  Flows will terminate for one of
four reasons:

1. A TCP flow session ends "normally" with a `FIN` or `RST` flag (`ClosureReason` 0)
2. The flow session has not seen a packet during an idle timeout period (`ClosureReason` 1)
3. The session traffic exceeds an active timeout period(`ClosureReason` 2)
4. We've reached an end-of-stream condition (`ClosureReason` 3)

Recall the previous example of running `ing` with `holiday-card.pcap`. Each of the
four flow records has the following JSON schema:

```
"ID": 1,      # A flow identifier guaranteed to be unique to this execution of ing
"Key": {      # A flow key with the standard 5-tuple and a VLAN identifier
  "Sip": {
    "Version": 4,
    "Address": "192.168.1.1"
  },
  "Dip": {
    "Version": 4,
    "Address": "192.168.1.2"
  },
  "Sport": 31337,
  "Dport": 80,
  "Proto": 6,
  "VlanID": 0
},
"StartTime": "1936-12-06T09:51:25-06:00",  # The time the first packet was seen
"EndTime": "1936-12-06T09:52:21-06:00",    # The time the flow was terminated
"NumPackets": 3,           # The number of valid packets in the flow
"NumBytes": 279,           # The number of total bytes from packets in the flow
"NumPayloadBytes": 117,    # The number of total payload bytes from packets in the flow
"FirstTCPFlags": 2,        # The TCP flags in from the first packet, if the session is TCP (0 for UDP)
"RestTCPFlags": 24,        # The union of all other TCP flags in the flow, if the sesion is TCP (0 for UDP)
"FirstTCPSequence": 0,     # The first packet TCP sequence number, if the session is TCP
"LastTCPSequence": 1,      # The last packet TCP sequence number, if the session is TCP
"ClosureReason": 2,        # The reason the flow closed
"SawFINOnly": false,       # For a TCP session, did we see a packet with a FIN but no ACK flag set?
"ActiveTimeout": "1936-12-06T10:21:25-06:00",  # The active timeout timestamp
"SawFirstPayload": true    # Did we see a packet with a non-zero payload?
```


### Banner files

Banners are currently extracted from the first packet in a flow session with a
non-zero payload. The payload is searched for a banner based on the banner terms in
[banner-terms.json](https://github.com/johnzachary/ing/blob/master/etc/banner-terms.json).
Many other banner terms are possible and you are free to add other types to the file
to discover other types of banners.  We currently use the
[IANA port number registry](http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
as a guide for creating banner terms.

Records in banner output files have the following format:

```
{
  "IP": {                               # IP address record
    "Version": 4,
    "Address": "192.168.1.1"
  },
  "Seen": "1936-12-06T09:52:21-06:00",  # Timestamp the banner was seen in the session
  "Port": 80,                           # On which service port the packet with the banner was seen
  "IANATag": "www-http",                # The IANA description of the service
  "Type": "client",                     # Can be a "client" or "server" banner
  "FlowID": 1,                          # The flow record in which the banner was seen
  "Banner": "Mu Dynamics"               # The banner string
}
```

## Disclaimer

This code it released as-is under the MIT License.