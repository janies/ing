// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"encoding/json"
	"log"
)

// DropFlows is used mainly for performance testing to ignore file writing.  I accepts a flow on
// the input channel, unmarshals it to JSON, and promptly ignores the result.
func DropFlows(done <-chan struct{}, in <-chan Flow) {
	go func() {
	Loop:
		for f := range in {
			select {
			case <-done:
				break Loop
			default:
				_, err := json.Marshal(f)
				if err != nil {
					// TODO: Better error handling here.
					log.Println("Cannot convert flow to JSON: ", f.String()) // Could go to lumberjack error log
					continue
				}
			}
		}
		// Force a timestamp on the last rotated file and delete the resulting empty flow.json file.
		wg.Done()
	}()
}
