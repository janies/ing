// This source code is covered by the license found in the LICENSE file.

package main

import (
	"sync"
	"time"
)

// These are global cache variables reused by several methods to avoid allocation and GC.
var v struct {
	ok   bool
	f    FlowCacheElem
	iptr *PickNode
	key  uint64
}

// FlowCacheElem embeds a Flow value and a pointer in the PickQueue that holds idle times for
// each flow.  This gives us an efficient way to delete from the idle queue when a flow is
// terminated directly from the flow map.
//
// TODO: A general solutions would use `interface{}` instead of a `Flow` type, but we want to
// avoid reflection in our application because it adds overhead. A TODO is to clean this up and
// make a package to share with others.
type FlowCacheElem struct {
	flow Flow
	iptr *PickNode
}

// NewFlowCache returns a pointer to an initialized FlowCache with the given capacity.
func NewFlowCache(capacity uint) *FlowCache {
	return &FlowCache{flows: make(map[uint64]FlowCacheElem, capacity), idle: NewPickQueue(),
		capacity: capacity}
}

// FlowCache combines a hash map and a pick-queue to provide an efficient way to terminate flows
// based on idle timeouts.  We fix the capacity and terminate older flows if we exhaust resources.
type FlowCache struct {
	flows    map[uint64]FlowCacheElem
	idle     *PickQueue
	capacity uint
}

// Insert inserts a new flow and it's idle timeout value and returns true if it doesn't exist in
// the cache.  It returns false if the value already exists in the cache.
func (fc *FlowCache) Insert(f Flow, key uint64, idle time.Time) bool {
	// IDEA: I'm not sure if we need to put in checks to guarantee consistency of lengths between
	// the map and the pick queue. Analaysis of the code demonstrates a tight coupling between
	// the hashmap and queue.
	if _, v.ok = fc.flows[key]; v.ok {
		return false // Key is already in hashmap, so don't enter and return false
	}
	v.f.flow = f
	v.f.iptr = fc.idle.PushIn(key, idle)
	fc.flows[key] = v.f
	return true
}

// Update updates a flow and its associated idle timeout value, and returns true if it exists in
// the cache.  It returns false if the value is not in the cache.
func (fc *FlowCache) Update(f Flow, key uint64, idleTime time.Time) bool {
	if v.f, v.ok = fc.flows[key]; !v.ok {
		return false // Key is not in hashmap, so nothing to update and return false
	}
	fc.idle.Pick(v.f.iptr)
	v.f.flow = f
	v.f.iptr = fc.idle.PushIn(key, idleTime)
	fc.flows[key] = v.f
	return true
}

// Remove removes a flow and its associated idle timeout from the cache. Return true if the flow
// was in the cache and removed; false otherwise.
func (fc *FlowCache) Remove(key uint64) (ok bool) {
	v.f, v.ok = fc.flows[key]
	if !v.ok {
		return false
	}
	delete(fc.flows, key)
	fc.idle.Pick(v.f.iptr)
	return true
}

// Fetch retrieves a flow value from the cache based on a key value but it does not remove the
// value.  This function can be used to check if a value is already in the cache by checking the
// return value of ok.
func (fc *FlowCache) Fetch(key uint64) (f Flow, ok bool) {
	v.f, v.ok = fc.flows[key]
	return v.f.flow, v.ok
}

// Purge cycles through the idle queue, removes flows that have expired, and applies the callback
// function to each flow value.
func (fc *FlowCache) Purge(t time.Time, cb func(Flow)) (count int) {
	for v.iptr = fc.idle.OutPtr; v.iptr != nil; v.iptr = v.iptr.next {
		if v.iptr.expiry.After(t) {
			// Assumes the expiry values are in monotonically increasing order in the pick queue.
			return
		}
		cb(fc.flows[v.iptr.key].flow)
		fc.Remove(v.iptr.key)
		count++
	}
	return
}

// PickNode is a node in a PickQueue.  Each node has a key into the flow hashmap and an expiry
// time at which the flow is considered terminated.
type PickNode struct {
	next   *PickNode
	prev   *PickNode
	key    uint64
	expiry time.Time
}

// NewPickQueue returns a new PickQueue
func NewPickQueue() *PickQueue {
	return &PickQueue{OutPtr: nil, InPtr: nil,
		pool: &sync.Pool{New: func() interface{} { return &PickNode{} }}}
}

// PickQueue is a queue with elements that can be removed ("picked") from any point in the queue,
// not just the front.  Elements can only be added at the front or (normally) back.  A pick queue
// combined with a hashmap with pointers to queue elements implements idle timeouts for flows.
// The fields of PickNode hold context necessary for enqueuing and dequeuing elements; the queue
// has no such logic embedded in its receiver methods.
type PickQueue struct {
	OutPtr *PickNode
	InPtr  *PickNode
	length uint
	pool   *sync.Pool
}

// PushIn enqueues a node at the back of a PickQueue with values key and expiry and returns a
// pointer to the node for reference (presumably in a hashmap).  Nodes are allocated from a
// sync.Pool, which helps manage the heap and GC. If the GC becomes a chokepoint, then we should
// look at a slab allocator for nodes.
func (pq *PickQueue) PushIn(key uint64, expiry time.Time) *PickNode {
	pn := pq.pool.Get().(*PickNode)
	pn.key = key
	pn.expiry = expiry
	pn.next = nil
	pn.prev = nil

	if pq.InPtr == nil {
		pq.OutPtr = pn
	} else {
		pq.InPtr.next = pn
	}
	pn.prev = pq.InPtr
	pq.InPtr = pn
	pq.length++
	return pn
}

// PopOut returns the key value of the head element in the PickQueue unless the queue is empty.
// Also, it returns true is the queue was head-popped and false if the queue was empty since  0 isn't
// a valid sentinel key value.
func (pq *PickQueue) PopOut() (key uint64, ok bool) {
	if pq.OutPtr == nil {
		return 0, false // Empty list -- need better return values
	}
	v.iptr = pq.OutPtr
	v.key = v.iptr.key
	pq.Pick(v.iptr)
	return v.key, true
}

// Pick removes a node from the PickQueue and returns the node to the sync.Pool.  We assume the
// node is an element of the PickQueue (i.e. we don't check membership).
func (pq *PickQueue) Pick(pn *PickNode) {
	// Only allow picking a double nil node if it is the only node in the list
	if pn.next == nil && pn.prev == nil && !(pq.OutPtr == pn && pq.InPtr == pn) {
		return
	}

	// Connect prev pointer to next pointer
	if pn.prev == nil {
		pq.OutPtr = pn.next
	} else {
		pn.prev.next = pn.next
	}

	// Connect next pointer to prev pointer
	if pn.next == nil {
		pq.InPtr = pn.prev
	} else {
		pn.next.prev = pn.prev
	}

	// Release the node back to the pool
	pq.pool.Put(pn)
	pq.length--
}
