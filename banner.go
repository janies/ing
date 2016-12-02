// This source code is covered by the license found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/cloudflare/ahocorasick"
)

// FirstPayload ...
type FirstPayload struct {
	IP      IPAddress // IP address of the banner
	FlowID  uint64
	Sport   uint16
	Dport   uint16
	Seen    time.Time // Time the banner was seen
	Payload [192]byte // Payload  (TODO: Pick a smart size for this array; 192 is a swag.)
}

// BannerTerm represents a search term for extracting banners from payloads.
// {"type": "client", "port": 80, "iana_tag": "www-http", "skip": true, "term": "\nUserAgent: "}
type BannerTerm struct {
	Type       string `json:"type"`
	Port       uint16 `json:"port"`
	IANATag    string `json:"iana_tag"`
	SkipTerm   bool   `json:"skip_term"`
	Term       string `json:"term"`
	ProxyTerm  string `json:"proxy_term"`
	Delimiters string `json:"delimiters"`
}

// Banner ...
type Banner struct {
	IP      IPAddress
	Seen    time.Time
	Port    uint16
	IANATag string
	Type    string // "client" or "server"
	FlowID  uint64
	Banner  string
}

func (b Banner) String() string {
	return fmt.Sprintf("%s, ip: %s, flow_id: %d, tag: %s/%d, type: %s, banner: %s",
		b.Seen.UTC().Format("2006-01-02 15:04:05.00000"), b.IP.Address, b.FlowID, b.IANATag,
		b.Port, b.Type, b.Banner)
}

// extractBanner ...
func extractBanner(payload []byte, term string, proxy string, skip bool, delimiters string) (banner string) {
	var index int
	var t string
	banner = string(payload)

	if proxy != "" {
		t = proxy
	} else {
		t = term
	}

	// Find the position where the term or its proxy start and search from that point.
	// Skip the term if required.
	// Otherwise, we just search from the beginning of the banner.
	if index = strings.Index(banner, t); index != -1 {
		banner = banner[index:]
		if skip {
			banner = strings.TrimPrefix(banner, t)
		}
	}

	// Remove delimiters from the banner.
	if index = strings.IndexAny(banner, delimiters); index != -1 {
		banner = banner[:index]
	}
	return
}

// ExtractBanners ...
func ExtractBanners(done <-chan struct{}, in <-chan FirstPayload) <-chan Banner {
	out := make(chan Banner, 256)

	go func() {
		defer close(out)

		var (
			fp   FirstPayload
			b    Banner
			hits []int
			i    int
		)

		// Build a banner term dictonary for searching payload strings.
		raw, err := ioutil.ReadFile(config.BannerTermsFile)
		if err != nil {
			log.Panicln("error: ", err)
		}
		var terms []BannerTerm
		if err = json.Unmarshal(raw, &terms); err != nil {
			log.Panicln("error: ", err)
		}

		var dictionary []string
		for i = range terms {
			dictionary = append(dictionary, terms[i].Term)
		}
		matcher := ahocorasick.NewStringMatcher(dictionary)

	Loop:
		for fp = range in {
			select {
			case <-done:
				break Loop
			default:
				// The values in `hits` should be indexed to `terms`.
				hits = matcher.Match(fp.Payload[:])
				for i = range hits {
					// Question: Can we have more than one hit in a banner? If so, is it an error?
					b.IP = fp.IP
					b.FlowID = fp.FlowID
					b.Seen = fp.Seen
					b.IANATag = terms[hits[i]].IANATag
					b.Type = terms[hits[i]].Type

					switch terms[hits[i]].Type {
					case "client":
						b.Port = terms[hits[i]].Port
						b.Banner = extractBanner(fp.Payload[:], terms[hits[i]].Term, terms[hits[i]].ProxyTerm,
							terms[hits[i]].SkipTerm, terms[hits[i]].Delimiters)
						out <- b
					case "server":
						b.Port = fp.Sport // Grab the real port, not the canonical.
						b.Banner = extractBanner(fp.Payload[:], terms[hits[i]].Term, terms[hits[i]].ProxyTerm,
							terms[hits[i]].SkipTerm, terms[hits[i]].Delimiters)
						out <- b
					case "clientserver":
						// SSH port 22 is the only type I've found for which this case applies.
						if fp.Sport == 22 { //terms[hits[i]].Port {
							// We have a server banner.
							b.Port = fp.Sport // Grab the real port, not the canonical.
							b.Type = "server"
							b.Banner = extractBanner(fp.Payload[:], terms[hits[i]].Term, terms[hits[i]].ProxyTerm,
								terms[hits[i]].SkipTerm, terms[hits[i]].Delimiters)
							out <- b
						}
						if fp.Dport == 22 { //terms[hits[i]].Port {
							// We have a client banner.
							b.Type = "client"
							b.Port = terms[hits[i]].Port
							b.Banner = extractBanner(fp.Payload[:], terms[hits[i]].Term, terms[hits[i]].ProxyTerm,
								terms[hits[i]].SkipTerm, terms[hits[i]].Delimiters)
							out <- b
						}
					}
					if config.Debug.PrintBanners {
						fmt.Println(b.String())
					}
				}
			}
		}
		wg.Done()
	}()
	return out
}
