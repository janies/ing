// This source code is covered by the license found in the LICENSE file.

package main

// IPAddress is a convenience structure that keeps us from passing around byte slices.  This is
// important for reusing variables like a cache in our goroutines since slice value-copy does not
// copy the underlying array (just the pointer, len, and cap values).
type IPAddress struct {
	Version byte
	Address string
}
