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
	"testing"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func TestResolveIPProtocol_Keywords(t *testing.T) {
	tests := []struct {
		keyword string
		want    uint16
	}{
		{"all", IPProtocolAny},
		{"icmp", IPProtocolICMP},
		{"tcp", IPProtocolTCP},
		{"udp", IPProtocolUDP},
		{"sctp", IPProtocolSCTP},
		{"gre", IPProtocolGRE},
		{"esp", IPProtocolESP},
		{"ah", IPProtocolAH},
	}
	for _, tt := range tests {
		t.Run(tt.keyword, func(t *testing.T) {
			p := intstr.FromString(tt.keyword)
			got, err := ResolveIPProtocol(&p)
			if err != nil {
				t.Fatalf("ResolveIPProtocol(%q) returned error: %v", tt.keyword, err)
			}
			if got != tt.want {
				t.Fatalf("ResolveIPProtocol(%q) = %d; want %d", tt.keyword, got, tt.want)
			}
		})
	}
}

func TestResolveIPProtocol_Numbers(t *testing.T) {
	tests := []struct {
		name  string
		value intstr.IntOrString
		want  uint16
	}{
		{"int zero is HOPOPT, not a wildcard", intstr.FromInt32(0), 0},
		{"int tcp", intstr.FromInt32(6), IPProtocolTCP},
		{"int gre", intstr.FromInt32(47), IPProtocolGRE},
		{"int highest protocol number", intstr.FromInt32(255), 255},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveIPProtocol(&tt.value)
			if err != nil {
				t.Fatalf("ResolveIPProtocol(%v) returned error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("ResolveIPProtocol(%v) = %d; want %d", tt.value, got, tt.want)
			}
		})
	}
}

func TestResolveIPProtocol_Rejected(t *testing.T) {
	tests := []struct {
		name  string
		value *intstr.IntOrString
	}{
		{"nil", nil},
		{"int above the protocol number range", ptr.To(intstr.FromInt32(256))},
		{"int below the protocol number range", ptr.To(intstr.FromInt32(-1))},
		{"number written as a string", ptr.To(intstr.FromString("6"))},
		{"zero written as a string", ptr.To(intstr.FromString("0"))},
		{"string above the protocol number range", ptr.To(intstr.FromString("256"))},
		{"string below the protocol number range", ptr.To(intstr.FromString("-1"))},
		{"unknown keyword", ptr.To(intstr.FromString("quic"))},
		{"keyword is case sensitive", ptr.To(intstr.FromString("TCP"))},
		{"empty string", ptr.To(intstr.FromString(""))},
		{"number with trailing text", ptr.To(intstr.FromString("47tcp"))},
		{"wildcard number is not spellable", ptr.To(intstr.FromString("65535"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveIPProtocol(tt.value)
			if err == nil {
				t.Fatalf("ResolveIPProtocol(%v) = %d; want an error", tt.value, got)
			}
		})
	}
}

func TestIPProtocolHasPorts(t *testing.T) {
	tests := []struct {
		name  string
		proto uint16
		want  bool
	}{
		{"tcp", IPProtocolTCP, true},
		{"udp", IPProtocolUDP, true},
		{"icmp", IPProtocolICMP, false},
		{"gre", IPProtocolGRE, false},
		{"esp", IPProtocolESP, false},
		{"sctp", IPProtocolSCTP, false},
		{"all", IPProtocolAny, false},
		{"unnamed number", 253, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPProtocolHasPorts(tt.proto); got != tt.want {
				t.Fatalf("IPProtocolHasPorts(%d) = %v; want %v", tt.proto, got, tt.want)
			}
		})
	}
}

func TestFormatIPProtocol(t *testing.T) {
	tests := []struct {
		name  string
		proto uint16
		want  string
	}{
		{"tcp", IPProtocolTCP, "tcp"},
		{"udp", IPProtocolUDP, "udp"},
		{"icmp", IPProtocolICMP, "icmp"},
		{"gre", IPProtocolGRE, "gre"},
		{"esp", IPProtocolESP, "esp"},
		{"ah", IPProtocolAH, "ah"},
		{"sctp", IPProtocolSCTP, "sctp"},
		{"wildcard", IPProtocolAny, "all"},
		{"zero is a real protocol number", 0, "0"},
		{"unnamed number", 253, "253"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatIPProtocol(tt.proto); got != tt.want {
				t.Fatalf("FormatIPProtocol(%d) = %q; want %q", tt.proto, got, tt.want)
			}
		})
	}
}

func TestFormatIPProtocolRoundTripsEveryKeyword(t *testing.T) {
	for _, keyword := range ipProtocolKeywords {
		t.Run(keyword.name, func(t *testing.T) {
			p := intstr.FromString(keyword.name)
			proto, err := ResolveIPProtocol(&p)
			if err != nil {
				t.Fatalf("ResolveIPProtocol(%q) returned error: %v", keyword.name, err)
			}
			if got := FormatIPProtocol(proto); got != keyword.name {
				t.Fatalf("FormatIPProtocol(%d) = %q; want %q", proto, got, keyword.name)
			}
		})
	}
}
