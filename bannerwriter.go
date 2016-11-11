// Copyright (c) 2016, Threat Trace, LLC. All rights reserved.

package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// WriteBanners ...
func WriteBanners(done <-chan struct{}, in <-chan Banner) {
	go func() {
		if err := os.MkdirAll(config.OutputPrefix, 0700); err != nil {
			// Error creating directory.
			// FIXME: Better error handling.
			log.Println("[Warning] Cannot create directory '", config.OutputPrefix, "'. Using './'")
			if err := os.MkdirAll("./", 0700); err != nil {
				log.Panicln("Cannot create directory './'. Stopping.")
			}
		}
		if config.OutputPrefix[len(config.OutputPrefix)-1] != '/' {
			config.OutputPrefix = config.OutputPrefix + "/"
		}
		filename := config.OutputPrefix + "banner" + config.OutputSlug + ".json"
		l := &lumberjack.Logger{Filename: filename, MaxSize: 100, MaxAge: 1}
		ticker := time.NewTicker(time.Duration(config.OutputRotationInterval) * time.Minute).C

	Loop:
		for b := range in {
			select {
			case <-done:
				break Loop
			case <-ticker:
				l.Rotate() // Rotate the log file every five minutes.
			default:
				bn, err := json.Marshal(b)
				if err != nil {
					// TODO: Better error handling here.
					log.Println("Cannot convert flow to JSON: ", b.String()) // Could go to lumberjack error log
					continue
				}
				l.Write(bn)
			}
		}
		// Force a timestamp on the last rotated file and delete the resulting empty flow.json file.
		l.Rotate()
		os.Remove(filename)
		l.Close()
		wg.Done()
	}()
}
