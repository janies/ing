// This source code is covered by the license found in the LICENSE file.
//
// Implementations of sort.Interface for collections that can be sorted by the package Sort.
// See https://golang.org/pkg/sort/#Interface

package main

// Int64Array is a sortable container conforming to the sort.Interface.
type Int64Array []int64

func (a Int64Array) Len() int           { return len(a) }
func (a Int64Array) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Int64Array) Less(i, j int) bool { return a[i] < a[j] }

// Uint64Array is a sortable container conformaing to the sort.Interface.
type Uint64Array []uint64

func (a Uint64Array) Len() int           { return len(a) }
func (a Uint64Array) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Uint64Array) Less(i, j int) bool { return a[i] < a[j] }
