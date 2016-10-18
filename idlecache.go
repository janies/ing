// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.
//
// NOTE: This is a *very* unoptimized implementation of an idle flow cache for our use case. It is
// a simple get-it-done approach using slices with terrible performance because of the massive amount
// slice resizing.  *DO NOT USE THIS VERSION BEYOND THE EARLY PROTOTYPE STAGE*
//
// TODO: A potentially better approach is a custom linked list that implicitly stores pointers with
// the elements, i.e. {next, hash, expiry}, with element allocations from a memory pool of size
// capacity. Go's `container/list` is not an option because elements are "external" to the list and
// use a "Value interface" to access the element.  Heap allocations (and assocaited GC activity) and
// general interfaces are not really our use case for an IdleCache.
//
// Some other ideas are to borrow from
//  [golang-lru](https://github.com/hashicorp/golang-lru)
//  [freecache](https://github.com/coocood/freecache)
//  [go-cache](https://godoc.org/github.com/robfig/go-cache)
//  [Memory pools using channels](http://stackoverflow.com/questions/38505830/how-to-implement-memory-pooling-in-golang)

package main

import "time"

// IdleEntry is an entry in an idle flow cache.
type IdleEntry struct {
	hash   uint64
	expiry time.Time
}

// IdleCache is a fixed-size cache based on slices.  It does not resize.
type IdleCache []IdleEntry

// NewIdleCache returns a new cache with the given capacity.
func NewIdleCache(capacity uint64) IdleCache {
	return make([]IdleEntry, 0, capacity)
}

// Add adds an cache entry corresponding to `hash` with an expiration time of `expiry`.
func (q *IdleCache) Add(e IdleEntry) bool {
	if len(*q) == cap(*q) {
		return false
	}
	*q = append(*q, e)
	return true
}

// Pop removes the first entry from the cache.
func (q *IdleCache) Pop() (e IdleEntry) {
	e = (*q)[0]
	*q = (*q)[1:]
	return
}

// Remove removes the entry corresponding to `hash` from the cache.
func (q *IdleCache) Remove(hash uint64) {
	for i := range *q {
		if (*q)[i].hash == hash {
			(*q) = append((*q)[:i], (*q)[i+1:]...)
			return
		}
	}
}

// Update updates the expiry for the `hash` entry and returns true. If no entry corresponds to
// `hash`, then the function returns false.
func (q *IdleCache) Update(hash uint64, expiry time.Time) bool {
	for i := range *q {
		if (*q)[i].hash == hash {
			//log.Println("Updating expiry for hash ", hash)
			e := (*q)[i]
			e.expiry = expiry
			(*q) = append((*q)[:i], (*q)[i+1:]...)
			*q = append(*q, e)
			return true
		}
	}
	return false
}

// Purge removes all entries from the cache that are older than `time`.
func (q *IdleCache) Purge(time time.Time) (count int) {
	for i := range *q {
		if (*q)[i].expiry.After(time) {
			(*q) = (*q)[i:]
			return
		}
		//log.Println("Purging flow ", (*q)[i].hash)
		count++
	}
	return
}
