VERSION := 0.1.0
BUILD_TIME := $(shell date -u +%Y-%m-%d_%I:%M:%S%p)
GIT_HASH := $(shell git rev-parse HEAD)

build:
	go get -u github.com/google/gopacket
	go get -u github.com/cloudflare/ahocorasick
	go get -u gopkg.in/natefinch/lumberjack.v2
	go build -ldflags \
        "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitHash=${GIT_HASH}"

test:
	go test -v

bench:
	go test -bench=.

clean:
	rm -rf ./ing output

.PHONY: build clean test bench
.DEFAULT_GOAL := build
