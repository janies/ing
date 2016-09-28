// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"fmt"
	"time"
)

// FlowTuple is a standard 5-tuple for IP flows
type FlowTuple struct {
	Sip   IPAddress
	Dip   IPAddress
	Sport uint16
	Dport uint16
	Proto uint8
}

const (
	fnvBasis = 14695981039346656037
	fnvPrime = 1099511628211
)

// fnvHash is based on the Fowler-Noll-Vo hash function (FNV-1a).
// Source. https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
func fnvHashSlice(b []byte) (h uint64) {
	h = fnvBasis
	for i := 0; i < len(b); i++ {
		h ^= uint64(b[i])
		h *= fnvPrime
	}
	return
}

// Hash provides a quick non-cryptographic hash value of a FlowTuple.
// Do not use for persistent key-value storage because it may change in future
// versions.
func (ft *FlowTuple) Hash() (h uint64) {
	h = fnvHashSlice(ft.Sip.Address[:]) + fnvHashSlice(ft.Dip.Address[:])
	h ^= uint64(ft.Sport)
	h *= fnvPrime
	h ^= uint64(ft.Dport)
	h *= fnvPrime
	h ^= uint64(ft.Proto)
	h *= fnvPrime
	return
}

// Copy ...
func (ft *FlowTuple) Copy(dst *FlowTuple) {
	dst.Sip = ft.Sip
	dst.Dip = ft.Dip
	dst.Sport = ft.Sport
	dst.Dport = ft.Dport
	dst.Proto = ft.Proto
}

func (ft FlowTuple) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d, proto: %d", ft.Sip.String(), ft.Sport, ft.Dip.String(),
		ft.Dport, ft.Proto)
}

// Flow is a complete description of a netflow session.
type Flow struct {
	ID               uint64
	Tuple            FlowTuple
	StartTime        time.Time
	EndTime          time.Time
	ActiveTimeout    time.Time
	NumPackets       uint64
	NumBytes         uint64
	NumPayloadBytes  uint64
	FirstTCPFlags    uint8
	RestTCPFlags     uint8
	FirstTCPSequence uint32
	LastTCPSequence  uint32
	ClosureCause     int
}

// Reasons for flow closure
const (
	ClosureNormal = iota
	ClosureActiveTimeout
	ClosureUnknown
)

// HasFINFlag ...
func (f *Flow) HasFINFlag() bool {
	return (f.RestTCPFlags&FIN == FIN) || (f.FirstTCPFlags&FIN == FIN)
}

// HasRSTFlag ...
func (f *Flow) HasRSTFlag() bool {
	return (f.FirstTCPFlags&RST == RST) || (f.RestTCPFlags&RST == RST)
}

// Equal uses the Equaler interface because we only care that the flow tuples are equal.
// NOTE: Strictly, we may not need the Equaler interace if we commit to IPAddress without slices.
func (f Flow) Equal(x Equaler) bool {
	if other, ok := x.(Flow); ok {
		return f.Tuple == other.Tuple
	}
	return false
}

func (f Flow) String() string {
	return fmt.Sprintf("{flow_id: %v, ip%v, %s, count: %v, bytes: %v, payload_bytes: %v, start: %s, end: %s}",
		f.ID, f.Tuple.Sip.Version, f.Tuple.String(), f.NumPackets, f.NumBytes, f.NumPayloadBytes,
		f.StartTime.String(), f.EndTime.String())
}
