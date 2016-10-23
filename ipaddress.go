// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"fmt"
	"net"
)

// IPAddress ...
type IPAddress struct {
	Version byte
	Address [16]byte
}

// CopyFromNetIP ...
func (ip *IPAddress) CopyFromNetIP(nip net.IP, isv4 bool) {
	ip.Address = zeroByteArray
	copy(ip.Address[:], nip)
	if isv4 {
		ip.Version = 4
		copy(ip.Address[:4], nip)
	} else {
		ip.Version = 6
		copy(ip.Address[:], nip)
	}
}

// IsIPV4 ...
func (ip *IPAddress) IsIPV4() bool {
	return ip.Version == 4
}

func (ip IPAddress) String() string {
	if ip.Version == 4 {
		return fmt.Sprintf("%s", net.IP(ip.Address[:4]).String())
	}
	return fmt.Sprintf("%s", net.IP(ip.Address[:]).String())
}
