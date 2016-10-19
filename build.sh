#!/bin/bash

if [ -f './ing' ]; then
    rm -rf './ing'
fi

# See semver.org for instructions on setting VERSION correctly
VERSION=0.1.0
go build -ldflags \
    "-X main.config.Version=${VERSION} -X main.config.BuildTime=`date -u +%Y-%m-%d_%I:%M:%S%p` -X main.config.GitHash=`git rev-parse HEAD`"

echo ""
echo "     ************************************************"
echo "        Don't forget to update the VERSION string."
echo "        The current VERSION is ${VERSION}."
echo "        See https://semver.org for rules."
echo "     ************************************************"
echo ""
