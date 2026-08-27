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

package v1alpha1

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"
)

// A policy rule selects traffic by IP protocol, and the data plane
// matches on the raw protocol number from the IP header. Rules are
// therefore written as numbers, and the keywords below are nothing more
// than a name for a handful of those numbers: the keyword "tcp" and the
// number 6 produce the exact same rule.
//
// A number is written as an integer and a keyword as a string, and the
// two forms never mix: "6" is a string that is not a keyword, so it is
// rejected rather than read as the number 6. The CRD schema draws the
// same line, so a spec means one thing at every layer.
//
// Keeping the table here, in the API package, is what lets the webhook,
// the controller and the daemon agree on what a rule means. A component
// that carries its own copy will eventually accept a protocol the data
// plane cannot install, or reject one it already installed.
//
// Users may write any number in [0, 255] even when it has no keyword,
// because that is the full range the IP header can express. The
// wildcard has to live outside that range: every number in it is a real
// protocol, so there is no spare value to overload.

// IPProtocolAny is the wildcard that matches every IP protocol. It sits
// above the [0, 255] protocol number range on purpose and mirrors
// POLICY_PROTO_ANY in the daemon's BPF maps.
const IPProtocolAny uint16 = 0xFFFF

// IP protocol numbers assigned by IANA for the protocols that have a
// keyword.
const (
	IPProtocolICMP uint16 = 1
	IPProtocolTCP  uint16 = 6
	IPProtocolUDP  uint16 = 17
	IPProtocolGRE  uint16 = 47
	IPProtocolESP  uint16 = 50
	IPProtocolAH   uint16 = 51
	IPProtocolSCTP uint16 = 132
)

// ipProtocolMaxNumber is the largest value the IP header's 8-bit
// protocol field can carry.
const ipProtocolMaxNumber = 255

// ipProtocolKeywords is the single keyword table. It is a slice rather
// than a map so the order stays fixed: error messages list the keywords
// from it, and users read the same order every time. Adding a protocol
// means adding one line here and one alternative to the CEL rules on
// the protocol fields.
//
// The element type is anonymous because crddoc publishes every struct
// type declared in this package to the user-facing API reference.
var ipProtocolKeywords = []struct {
	name  string
	proto uint16
}{
	{"icmp", IPProtocolICMP},
	{"tcp", IPProtocolTCP},
	{"udp", IPProtocolUDP},
	{"gre", IPProtocolGRE},
	{"esp", IPProtocolESP},
	{"ah", IPProtocolAH},
	{"sctp", IPProtocolSCTP},
	{"all", IPProtocolAny},
}

var (
	ipProtocolByKeyword = buildIPProtocolByKeyword()
	ipProtocolNames     = buildIPProtocolNames()
	ipProtocolHint      = buildIPProtocolHint()
)

func buildIPProtocolByKeyword() map[string]uint16 {
	byKeyword := make(map[string]uint16, len(ipProtocolKeywords))
	for _, keyword := range ipProtocolKeywords {
		byKeyword[keyword.name] = keyword.proto
	}
	return byKeyword
}

func buildIPProtocolNames() map[uint16]string {
	names := make(map[uint16]string, len(ipProtocolKeywords))
	for _, keyword := range ipProtocolKeywords {
		names[keyword.proto] = keyword.name
	}
	return names
}

func buildIPProtocolHint() string {
	names := make([]string, 0, len(ipProtocolKeywords))
	for _, keyword := range ipProtocolKeywords {
		names = append(names, keyword.name)
	}
	return fmt.Sprintf("must be a keyword (%s) or an integer IP protocol number in [0, %d]",
		strings.Join(names, ", "), ipProtocolMaxNumber)
}

// ResolveIPProtocol turns a user-written protocol into the number the
// data plane matches on. A number must be written as an integer; a
// string is read as a keyword and nothing else, so a quoted number such
// as "6" is an error rather than an alias for 6.
//
// Every caller must handle the error. A protocol that does not resolve
// is a rule whose meaning is unknown, and guessing one would silently
// filter traffic the user never described.
func ResolveIPProtocol(p *intstr.IntOrString) (uint16, error) {
	if p == nil {
		return 0, errors.New("protocol is not set")
	}

	switch p.Type {
	case intstr.Int:
		number := p.IntValue()
		if number < 0 || number > ipProtocolMaxNumber {
			return 0, fmt.Errorf("IP protocol number %d is out of range: %s", number, ipProtocolHint)
		}
		return uint16(number), nil
	case intstr.String:
		if proto, ok := ipProtocolByKeyword[p.StrVal]; ok {
			return proto, nil
		}
		return 0, fmt.Errorf("protocol %q is not a keyword: %s", p.StrVal, ipProtocolHint)
	default:
		return 0, fmt.Errorf("protocol holds an unsupported value type %d: %s", p.Type, ipProtocolHint)
	}
}

// IPProtocolHasPorts reports whether a rule for this protocol may carry
// ports.
//
// Only TCP and UDP qualify. SCTP does have ports, but the data plane
// never parses an SCTP header, so a port written on an SCTP rule would
// be accepted at admission and then ignored on the wire.
func IPProtocolHasPorts(proto uint16) bool {
	return proto == IPProtocolTCP || proto == IPProtocolUDP
}

// FormatIPProtocol renders a resolved protocol for error messages and
// status. Protocols that have a keyword render as the keyword, the
// wildcard renders as "all", and everything else renders as its number.
func FormatIPProtocol(proto uint16) string {
	if name, ok := ipProtocolNames[proto]; ok {
		return name
	}
	return strconv.FormatUint(uint64(proto), 10)
}
