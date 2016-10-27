// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/layers"
)

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

// FlowKey is a standard 5-tuple plus a Vlan ID for 802.1q networks
type FlowKey struct {
	Sip    IPAddress
	Dip    IPAddress
	Sport  uint16
	Dport  uint16
	Proto  layers.IPProtocol
	VlanID uint16
}

// Hash provides a quick non-cryptographic hash value of a FlowKey.
// Do not use for persistent key-value storage because it may change in future
// versions.
func (ft *FlowKey) Hash() (h uint64) {
	h = fnvHashSlice(ft.Sip.Address[:]) + fnvHashSlice(ft.Dip.Address[:])
	h ^= uint64(ft.Sport)
	h *= fnvPrime
	h ^= uint64(ft.Dport)
	h *= fnvPrime
	h ^= uint64(ft.Proto)
	h *= fnvPrime
	h ^= uint64(ft.VlanID)
	h *= fnvPrime
	return
}

func (ft FlowKey) String() string {
	switch ft.Proto {
	case layers.IPProtocolTCP:
		fallthrough
	case layers.IPProtocolUDP:
		if ft.Sip.Version == 4 {
			return fmt.Sprintf("%s %s:%d -> %s:%d", ft.Proto.String(), ft.Sip.String(), ft.Sport,
				ft.Dip.String(), ft.Dport)
		}
		return fmt.Sprintf("%s %s.%d -> %s.%d", ft.Proto.String(), ft.Sip.String(), ft.Sport,
			ft.Dip.String(), ft.Dport)
	case layers.IPProtocolICMPv4:
		return fmt.Sprintf(" %s %d:%d %s -> %s", ft.Proto.String(),
			layers.ICMPv4TypeCode(ft.Sport).Type(), layers.ICMPv4TypeCode(ft.Sport).Code(),
			ft.Sip.String(), ft.Dip.String())
	case layers.IPProtocolICMPv6:
		return fmt.Sprintf(" %s %d:%d %s -> %s", ft.Proto.String(),
			layers.ICMPv6TypeCode(ft.Sport).Type(), layers.ICMPv6TypeCode(ft.Sport).Code(),
			ft.Sip.String(), ft.Dip.String())
	default:
		return fmt.Sprintf("* Unknown flow *")
	}
}

// Flow is a complete description of a netflow session.
type Flow struct {
	ID               uint64
	Key              FlowKey
	StartTime        time.Time
	EndTime          time.Time
	NumPackets       uint64
	NumBytes         uint64
	NumPayloadBytes  uint64
	FirstTCPFlags    uint8
	RestTCPFlags     uint8
	FirstTCPSequence uint32
	LastTCPSequence  uint32
	ClosureReason    int
	SawFINOnly       bool
	ActiveTimeout    time.Time
}

// Reasons for flow closure
const (
	ClosureNormal = iota
	ClosureActiveTimeout
	ClosureIdleTimeout
	ClosurePcapEOF
	ClosureResourceExhaustion
)

// HasFINFlag ...
func (f *Flow) HasFINFlag() bool {
	return (f.RestTCPFlags&FIN == FIN) || (f.FirstTCPFlags&FIN == FIN)
}

// HasRSTFlag ...
func (f *Flow) HasRSTFlag() bool {
	return (f.FirstTCPFlags&RST == RST) || (f.RestTCPFlags&RST == RST)
}

// Equal uses the Equaler interface because we only care that the flow keys are equal.
// NOTE: Strictly, we may not need the Equaler interace if we commit to IPAddress without slices.
func (f Flow) Equal(x Equaler) bool {
	if other, ok := x.(Flow); ok {
		return f.Key == other.Key
	}
	return false
}

func (f Flow) String() string {
	return fmt.Sprintf("%s - %s (%s) %s (count: %v, bytes: %v, payload_bytes: %v)",
		f.StartTime.UTC().Format("2006-01-02 15:04:05.00000"), f.EndTime.UTC().Format("15:04:05.00000"),
		time.Duration(f.EndTime.Sub(f.StartTime)),
		f.Key.String(), f.NumPackets, f.NumBytes, f.NumPayloadBytes)
}

// AssignFlows is the main computation for assigning packets to flows and terminating flows based
// on specific termination conditions:
// 1. A TCP session ends normally with FIN or a RST flag. We track if we see a FIN without an ACK
//    since it may be considered anomalous.
// 2. The map is full (terminate the oldest flows to free up resources).
// 3. See a packet after ActiveTimeout seconds.
// 4. A flow doesn't see a packet after IdleTimeout seconds (PurgeIdleFlows() receiver method).
//
// TODO: Implement flow termination logic for reasons 2.
func AssignFlows(done <-chan struct{}, in <-chan MetaPacket) <-chan Flow {
	out := make(chan Flow, 256)
	go func() {
		defer close(out)
		const (
			capacity               = 10000000 // Ten million is pretty high
			oooBound time.Duration = 5 * time.Microsecond
		)
		// These are cache variables that help us avoid allocating new variables and minimize GC
		// activity in the goroutine.
		var (
			flowCache        = NewFlowCache(capacity)
			currentTimestamp time.Time
			mp               MetaPacket
			numFlows         uint64
			key              FlowKey
			flow             Flow
			hash             uint64
			oooPacket        bool
			ok               bool
			deltaTimestamp   time.Duration
			activeTimeout    = time.Duration(config.ActiveTimeout) * time.Second
			idleTimeout      = time.Duration(config.IdleTimeout) * time.Second
		)

	Loop:
		for mp = range in {
			select {
			case <-done:
				break Loop
			default:
				// Update the current timestamp
				deltaTimestamp = mp.timestamp.Sub(currentTimestamp)
				oooPacket = false
				if deltaTimestamp < -oooBound {
					continue Loop // Drop packet because it's too old.
				} else if (deltaTimestamp < 0) && (deltaTimestamp >= -oooBound) {
					oooPacket = true // Out of order but keep it
					log.Println("Out of order packet at ", mp.timestamp.String())
				} else {
					currentTimestamp = mp.timestamp
				}

				// Purge inactive flows from the map and idle cache.  We make things easy and use a
				// closure for the callback to IdleCache.Purge().
				flowCache.Purge(currentTimestamp, func(flow Flow) {
					if config.FilterSmallFlows && (flow.Key.Proto == layers.IPProtocolTCP) &&
						(flow.NumPackets < 4) {
						return
					}
					if config.Debug.PrintFlows {
						fmt.Println(flow.String())
					}
					flow.ClosureReason = ClosureIdleTimeout
					out <- flow
				})

				// Construct a flow key and its hash.
				// REVIEW: This might be inefficient. Take a look at the sync/atomic Value type.
				key.Sip = mp.sip
				key.Dip = mp.dip
				key.Sport = mp.sport
				key.Dport = mp.dport
				key.Proto = mp.protocol
				key.VlanID = mp.vlanid
				hash = key.Hash()

				// Look up the key in the flow map.
				// If it returns a hit, then we check if the packet triggers an active timeout
				// termination. If so, we send the current flow with the key on the output channel
				// and fall out of the branch to the code below, thus creating another flow with
				// this key.  If the packet does not cause an active timeout, we may still terminate
				// the flow if the packet is a TCP packet and has [FIN, ACK] or [RST] flags set.
				// Otherwise, we update the flow and return.
				// If there is no hit in the map table for this key, we create a new flow and add
				// it to the table.
				if flow, ok = flowCache.Fetch(hash); ok {
					// Flow exists in the set. Update and terminate, if necessary.
					// First, check for an active timeout for the flow.
					if mp.timestamp.After(flow.ActiveTimeout) {
						// Termination reason 3: Active timeout
						flowCache.Remove(hash)
						if config.FilterSmallFlows && (flow.Key.Proto == layers.IPProtocolTCP) &&
							(flow.NumPackets < 4) {
							// This condition filters out small flows if the config is set.
							continue Loop
						}
						if config.Debug.PrintFlows {
							fmt.Println(flow.String())
						}
						flow.ClosureReason = ClosureActiveTimeout
						out <- flow
						// NOTE: Since this is a continuation of a flow, we create a new flow by
						// dropping out of this branch. DO NOT RETURN.
					} else {
						// This branch updates an exising flow entry and, if applicable, terminates
						// the flow if the packet is TCP and the terminal flags are set.
						// NOTE. This branch *must* continue the loop.
						if !oooPacket || (flow.EndTime.Before(mp.timestamp)) {
							flow.EndTime = mp.timestamp
						}
						flow.NumPackets++
						flow.NumBytes += uint64(mp.packetLength)
						flow.NumPayloadBytes += uint64(mp.payloadLength)

						if mp.protocol == layers.IPProtocolTCP {
							flow.RestTCPFlags |= mp.tcpFlags
							flow.LastTCPSequence = mp.tcpSeq
							// Termination reason 1: Normal TCP session ended with FIN or RST
							if (mp.tcpFlags&FIN == FIN) || (mp.tcpFlags&RST == RST) {
								if (mp.tcpFlags&FIN == FIN) && (mp.tcpFlags&ACK == 0x00) {
									flow.SawFINOnly = true
								}
								if config.Debug.PrintFlows {
									fmt.Println(flow.String())
								}
								flowCache.Remove(hash)
								// This condition filters out small flows if the config is set.
								if !(config.FilterSmallFlows && flow.NumPackets < 4) {
									out <- flow
								}
								continue Loop
							}
						}
						// We update a non-TCP flow or one that did not terminate normally, i.e.
						// termination reason 1.
						flowCache.Update(flow, hash, mp.timestamp.Add(idleTimeout))
						continue Loop
					}
				}
				// Define a new flow.
				numFlows++
				flow.ID = numFlows
				flow.Key = key
				flow.StartTime = mp.timestamp
				flow.EndTime = mp.timestamp
				flow.ActiveTimeout = mp.timestamp.Add(activeTimeout)
				flow.ClosureReason = ClosureNormal
				flow.NumPackets = 1
				flow.NumBytes = uint64(mp.packetLength)
				flow.NumPayloadBytes = uint64(mp.payloadLength)
				if mp.protocol == layers.IPProtocolTCP {
					flow.FirstTCPFlags = mp.tcpFlags
					flow.RestTCPFlags = 0
					flow.FirstTCPSequence = mp.tcpSeq
					flow.LastTCPSequence = mp.tcpSeq
					flow.SawFINOnly = false
				}
				flowCache.Insert(flow, hash, mp.timestamp.Add(idleTimeout))
			}
		}

		// Purge remaining flows from the flow cache.  We make things easy and use a
		// closure for the callback to IdleCache.Purge().
		flowCache.Purge(currentTimestamp.Add(activeTimeout), func(flow Flow) {
			if config.FilterSmallFlows && (flow.Key.Proto == layers.IPProtocolTCP) &&
				(flow.NumPackets < 4) {
				return
			}
			if config.Debug.PrintFlows {
				fmt.Println(flow.String())
			}
			flow.ClosureReason = ClosureIdleTimeout
			out <- flow
		})
		stats.TotalFlows += numFlows
		wg.Done()
	}()
	return out
}
