// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/layers"
)

const (
	uptick    time.Duration = PcapTimeout * time.Millisecond // PCAP timeouts are in miliseconds
	oooBounds time.Duration = 5 * time.Microsecond           // Set to 5 microseconds
)

// FlowSet aggregates flows.
type FlowSet struct {
	FlowMap          map[uint64]Flow
	Idle             IdleCache
	ActiveTimeout    time.Duration
	IdleTimeout      time.Duration
	CurrentTimestamp time.Time
	Capacity         uint64
	NumFlows         uint64
	writer           *FlowWriter
}

// NewFlowSet ...
func NewFlowSet(active, idle uint, capacity uint64) *FlowSet {
	return &FlowSet{FlowMap: make(map[uint64]Flow, capacity), Idle: NewIdleCache(capacity),
		ActiveTimeout: time.Duration(active) * time.Second,
		IdleTimeout:   time.Duration(idle) * time.Second, Capacity: capacity,
		writer: NewFlowWriter("./output/", 100)}
}

// UpdateClock is called if there are no packets received on the interface.  It ensures the FlowSet
// clock is moved forward and flows are expired in the absence of traffic.
func (fs *FlowSet) UpdateClock() {
	if fs.CurrentTimestamp.IsZero() {
		return
	}
	fs.CurrentTimestamp.Add(uptick)
	log.Println("Flow set clock forwarded to ", fs.CurrentTimestamp.String())
}

func (fs *FlowSet) Close() {
	fs.writer.Close()
}

// Cache variables for Add.  We don't need to reallocate these variable for every packet.
var (
	tuple          FlowTuple
	flow           Flow
	idle           IdleEntry
	hash           uint64
	oooPacket      bool
	ok             bool
	terminateFlow  bool
	deltaTimestamp time.Duration
)

// Add a packet to the flow set based on the packet's tuple value.
func (fs *FlowSet) Add(mp MetaPacket) {
	// Update current timestamp.
	deltaTimestamp = mp.timestamp.Sub(fs.CurrentTimestamp)
	oooPacket = false
	if deltaTimestamp < -oooBounds {
		return // Drop packet because it's too old.
	} else if (deltaTimestamp < 0) && (deltaTimestamp >= -oooBounds) {
		oooPacket = true // Out of order but keep it
		log.Println("Out of order packet at ", mp.timestamp.String())
	} else {
		fs.CurrentTimestamp = mp.timestamp
	}

	// Construct a flow tuple and its hash.
	// REVIEW This might be inefficient. Take a look at the sync/atomic Value type.
	tuple.Sip = mp.sip
	tuple.Dip = mp.dip
	tuple.Sport = mp.sport
	tuple.Dport = mp.dport
	tuple.Proto = uint8(mp.protocol)
	hash = tuple.Hash()

	// Reasons for terminating a flow:
	// 1. A TCP session ends normally (see a FIN and ACK, or a RST flag).
	// 2. The map is full (terminate the oldest flows).
	// 3. See a packet after ActiveTimeout seconds.
	// 4. Don't see a packet after IdleTimeout seconds (PurgeIdleFlows() receiver method).

	// TODO: Implement flow termination logic for reasons 2 and 4.  These checks should occur
	// outside of this function.

	if flow, ok = fs.FlowMap[hash]; ok {
		// Flow exists in the set. Update and terminate, if necessary.
		// First, check for an active timeout for the flow.
		if flow.ActiveTimeout.Before(mp.timestamp) {
			// Termination reason 3
			flow.ClosureCause = ClosureActiveTimeout
			if DebugPrintFlows {
				fmt.Println(flow.String())
			}
			fs.writer.Write(flow)
			delete(fs.FlowMap, hash)
			fs.Idle.Remove(hash)
			// Since this is a continuation of a flow, we create a new flow by dropping out of
			// this branch.
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
				if (flow.HasFINFlag() && (mp.tcpFlags&ACK) != 0) || flow.HasRSTFlag() {
					// Termination reason 1
					terminateFlow = true
				}
				flow.RestTCPFlags |= mp.tcpFlags
				flow.LastTCPSequence = mp.tcpSeq
			}
			if terminateFlow {
				if DebugPrintFlows {
					fmt.Println(flow.String())
				}
				fs.writer.Write(flow)
				delete(fs.FlowMap, hash)
				fs.Idle.Remove(hash)
			} else {
				fs.FlowMap[hash] = flow
				fs.Idle.Update(hash, mp.timestamp.Add(fs.IdleTimeout))
			}
			return
		}
	}
	// Define a new flow.
	fs.NumFlows++
	flow.ID = fs.NumFlows
	flow.Tuple = tuple
	flow.StartTime = mp.timestamp
	flow.EndTime = mp.timestamp
	flow.ActiveTimeout = mp.timestamp.Add(fs.ActiveTimeout)
	flow.ClosureCause = ClosureNormal
	flow.NumPackets = 1
	flow.NumBytes = uint64(mp.packetLength)
	flow.NumPayloadBytes = uint64(mp.payloadLength)
	flow.FirstTCPFlags = mp.tcpFlags
	flow.RestTCPFlags = 0
	flow.FirstTCPSequence = mp.tcpSeq
	flow.LastTCPSequence = mp.tcpSeq

	idle.hash = hash
	idle.expiry = mp.timestamp.Add(fs.IdleTimeout)

	// Next, check the flow map and ensure there is room to potentially add a new
	// record. We the map is at capacity, pop the oldest flow.
	// NOTE: Make sure the map and idle cache are the same size!
	// TODO: Map and idle queue resizing (EXPENSIVE)
	if uint64(len(fs.FlowMap)) == fs.Capacity {
		if len(fs.FlowMap) != len(fs.Idle) {
			log.Panicf("Flow map and idle timeout cache are out of sync after %v packets and %v flows!",
				totalPackets, fs.NumFlows)
		}
		e := fs.Idle.Pop()
		if DebugPrintFlows {
			log.Println("Capacity alert! Early close for: ", fs.FlowMap[e.hash].String())
		}
		delete(fs.FlowMap, e.hash)
	}
	fs.FlowMap[hash] = flow
	fs.Idle.Add(idle)
}
