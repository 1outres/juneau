/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package addressrange parses the "start-end" address form that ARP-mode
// AddressPool entries use.
package addressrange

import (
	"errors"
	"net/netip"
	"strings"
)

// The sentinel messages are the text the AddressPool webhook reports on the
// offending spec.addresses entry, so they read as validation rules.
var (
	ErrMalformed = errors.New("must be in start-end format")
	ErrNotIPv4   = errors.New("must be IPv4 range")
	ErrReversed  = errors.New("range start must be <= end")
)

const separator = "-"

// ParseIPv4Range parses "<start>-<end>" into its two inclusive bounds. Both
// bounds are returned in 4-byte form even when written as IPv4-mapped IPv6.
func ParseIPv4Range(raw string) (netip.Addr, netip.Addr, error) {
	parts := strings.Split(raw, separator)
	if len(parts) != 2 {
		return netip.Addr{}, netip.Addr{}, ErrMalformed
	}

	start, err := parseIPv4(parts[0])
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	end, err := parseIPv4(parts[1])
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if start.Compare(end) > 0 {
		return netip.Addr{}, netip.Addr{}, ErrReversed
	}
	return start, end, nil
}

func parseIPv4(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, ErrNotIPv4
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, ErrNotIPv4
	}
	return addr, nil
}
