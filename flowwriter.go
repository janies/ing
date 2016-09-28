// Copyright (c) 2016 Threat Trace, LLC. All rights reserved.

package main

import (
	"encoding/json"
	"log"
	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

func NewFlowWriter(outputPrefix string, maxFileSize int) *FlowWriter {
	if err := os.MkdirAll(outputPrefix, 0700); err != nil {
		// Error creating directory.
		// TODO: Better error handling.
		log.Panicln("Cannot create directory '", outputPrefix, "'")
	}
	filename := outputPrefix + "flow.json"
	l := &lumberjack.Logger{Filename: filename, MaxSize: maxFileSize, MaxAge: 1}
	return &FlowWriter{log: l, outputPrefix: outputPrefix}
}

type FlowWriter struct {
	log          *lumberjack.Logger
	outputPrefix string
}

func (fw *FlowWriter) Write(f Flow) {
	b, err := json.Marshal(f)
	if err != nil {
		// TODO: Better error handling here.  Since this receiver method may be a goroutine, we
		// need to be smarter about concurrency and error handling.
		log.Println("Cannot convert flow to JSON: ", f.String()) // Could go to lumberjack error log
		return
	}
	fw.log.Write(b)
}

func (fw *FlowWriter) Close() {
	// Force a timestamp on the last output file and remove the new file (which is empty).
	fw.log.Rotate()
	os.Remove(fw.log.Filename)
	fw.log.Close()
}
