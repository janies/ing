// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"fmt"
	"log"
	"sort"
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

// FlowTuple is a standard 5-tuple for IP flows
type FlowTuple struct {
	Sip   IPAddress
	Dip   IPAddress
	Sport uint16
	Dport uint16
	Proto layers.IPProtocol
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
	ClosureReason    int
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

// Equal uses the Equaler interface because we only care that the flow tuples are equal.
// NOTE: Strictly, we may not need the Equaler interace if we commit to IPAddress without slices.
func (f Flow) Equal(x Equaler) bool {
	if other, ok := x.(Flow); ok {
		return f.Tuple == other.Tuple
	}
	return false
}

func (f Flow) String() string {
	return fmt.Sprintf("%s - %s (%s) %s (count: %v, bytes: %v, payload_bytes: %v)",
		f.StartTime.UTC().Format("2006-01-02 15:04:05.00000"), f.EndTime.UTC().Format("15:04:05.00000"),
		time.Duration(f.EndTime.Sub(f.StartTime)),
		f.Tuple.String(), f.NumPackets, f.NumBytes, f.NumPayloadBytes)
}

// AssignFlows ...
func AssignFlows(done <-chan struct{}, in <-chan MetaPacket) <-chan Flow {
	out := make(chan Flow, 256)
	go func() {
		defer close(out)
		const (
			capacity               = 10000000
			oooBound time.Duration = 5 * time.Microsecond
		)
		var (
			flowMap          = make(map[uint64]Flow, capacity)
			idleCache        = NewIdleCache(capacity)
			currentTimestamp time.Time
			numFlows         uint64
			tuple            FlowTuple
			flow             Flow
			idle             IdleElem
			hash             uint64
			oooPacket        bool
			ok               bool
			terminateFlow    bool
			deltaTimestamp   time.Duration
			activeTimeout    = time.Duration(config.ActiveTimeout) * time.Second
			idleTimeout      = time.Duration(config.IdleTimeout) * time.Second
		)

	Loop:
		for mp := range in {
			select {
			case <-done:
				break Loop
			default:
				// Reasons for terminating a flow:
				// 1. A TCP session ends normally (see a [FIN,ACK] or a [RST] flag).
				// 2. The map is full (terminate the oldest flows).
				// 3. See a packet after ActiveTimeout seconds.
				// 4. Don't see a packet after IdleTimeout seconds (PurgeIdleFlows() receiver method).
				//
				// TODO: Implement flow termination logic for reasons 2.

				// Purge inactive flows from the map and idle cache.  We make things easy and use a
				// closure for the callback to IdleCache.Purge().
				idleCache.Purge(mp.timestamp, func(hash uint64) {
					if flow, ok = flowMap[hash]; ok {
						if config.Debug.PrintFlows {
							fmt.Println(flow.String())
						}
						flow.ClosureReason = ClosureIdleTimeout
						delete(flowMap, hash)
						if config.FilterSmallFlows && (flow.Tuple.Proto == layers.IPProtocolTCP) &&
							(flow.NumPackets < 4) {
							return
						}
						out <- flow
					}
				})

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

				// Construct a flow tuple and its hash.
				// REVIEW: This might be inefficient. Take a look at the sync/atomic Value type.
				tuple.Sip = mp.sip
				tuple.Dip = mp.dip
				tuple.Sport = mp.sport
				tuple.Dport = mp.dport
				tuple.Proto = mp.protocol
				hash = tuple.Hash()
				if flow, ok = flowMap[hash]; ok {
					// Flow exists in the set. Update and terminate, if necessary.
					// First, check for an active timeout for the flow.
					if flow.ActiveTimeout.Before(mp.timestamp) {
						// Termination reason 3
						flow.ClosureReason = ClosureActiveTimeout
						if config.Debug.PrintFlows {
							fmt.Println(flow.String())
						}
						delete(flowMap, hash)
						idleCache.Remove(hash)
						if config.FilterSmallFlows && (flow.Tuple.Proto == layers.IPProtocolTCP) &&
							(flow.NumPackets < 4) {
							continue Loop
						}
						out <- flow
						// NOTE: Since this is a continuation of a flow, we create a new flow by
						// dropping out of this branch. DO NOT RETURN.
					} else {
						// This branch updates an exising flow and, if applicable, terminates the flow.
						// NOTE. This branch *must* return.
						if !oooPacket || (flow.EndTime.Before(mp.timestamp)) {
							flow.EndTime = mp.timestamp
						}
						flow.NumPackets++
						flow.NumBytes += uint64(mp.packetLength)
						flow.NumPayloadBytes += uint64(mp.payloadLength)
						terminateFlow = false
						if mp.protocol == layers.IPProtocolTCP {
							if (mp.tcpFlags&(FIN|ACK) == (FIN | ACK)) || (mp.tcpFlags&RST == RST) {
								// Termination reason 1
								terminateFlow = true
							}
							flow.RestTCPFlags |= mp.tcpFlags
							flow.LastTCPSequence = mp.tcpSeq
						}
						if terminateFlow {
							if config.Debug.PrintFlows {
								fmt.Println(flow.String())
							}
							delete(flowMap, hash)
							idleCache.Remove(hash)
							if config.FilterSmallFlows && (flow.Tuple.Proto == layers.IPProtocolTCP) &&
								(flow.NumPackets < 4) {
								continue Loop
							}
							out <- flow
						} else {
							flowMap[hash] = flow
							idleCache.Update(hash, mp.timestamp.Add(idleTimeout))
						}
						continue Loop
					}
				}
				// Define a new flow.
				numFlows++
				flow.ID = numFlows
				flow.Tuple = tuple
				flow.StartTime = mp.timestamp
				flow.EndTime = mp.timestamp
				flow.ActiveTimeout = mp.timestamp.Add(activeTimeout)
				flow.ClosureReason = ClosureNormal
				flow.NumPackets = 1
				flow.NumBytes = uint64(mp.packetLength)
				flow.NumPayloadBytes = uint64(mp.payloadLength)
				flow.FirstTCPFlags = mp.tcpFlags
				flow.RestTCPFlags = 0
				flow.FirstTCPSequence = mp.tcpSeq
				flow.LastTCPSequence = mp.tcpSeq

				idle.hash = hash
				idle.expiry = mp.timestamp.Add(idleTimeout)

				// Next, check the flow map and ensure there is room to potentially add a new
				// record. We the map is at capacity, pop the oldest flow.
				// NOTE: Make sure the map and idle cache are the same size!
				// TODO: Map and idle queue resizing (EXPENSIVE)
				if uint64(len(flowMap)) == capacity {
					if len(flowMap) != len(idleCache) {
						log.Panicf("Flow map (len=%v) and idle timeout cache (len=%v, cap=%v) are out of sync after %v packets and %v flows!",
							len(flowMap), len(idleCache), cap(idleCache), stats.TotalPackets, numFlows)
					}
					e := idleCache.Pop()
					if config.Debug.PrintFlows {
						log.Println("Capacity alert! Early close for: ", flowMap[e.hash].String())
					}
					delete(flowMap, e.hash)
				}
				flowMap[hash] = flow
				idleCache.Add(idle)
			}
		}
		// Go randomizes key iteration order, so we need to grab the keys, sort them, and access
		// the values in sorted order.  This is ok here because it's the end of the goroutine and
		// there are presumably no more packets to process.
		var keys Uint64Array
		for k := range flowMap {
			keys = append(keys, k)
		}
		sort.Sort(keys)
		for _, k := range keys {
			if config.Debug.PrintFlows {
				fmt.Println(flowMap[k])
			}
			out <- flowMap[k]
		}
		stats.TotalFlows += numFlows
		wg.Done()
	}()
	return out
}
