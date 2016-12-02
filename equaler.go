// This source code is covered by the license found in the LICENSE file.

package main

// Equaler is an interface that lets us compare composite or complex structs using a subset of
// fields.  See https://golang.org/doc/faq#t_and_equal_interface.
type Equaler interface {
	Equal(Equaler) bool
}
