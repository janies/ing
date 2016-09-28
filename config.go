// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

// These are Ing configuration variables.  We may want to put them in a struct or make a Config
// type if they grow in number.
var (
	DebugPrintPackets bool
	DebugPrintFlows   bool
	ActiveTimeout     uint
	IdleTimeout       uint
)

// Ing constants
const (
	IdlePacketDuration = 10
	PcapTimeout        = 1000 // PCAP timeout values are expressed as milliseconds
)
