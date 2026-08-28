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
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestParsePodSecurityGroups(t *testing.T) {
	cases := []struct {
		name       string
		annotation string
		want       []string
	}{
		{name: "empty", annotation: "", want: nil},
		{name: "blank", annotation: "  ", want: nil},
		{name: "single", annotation: "sg-a", want: []string{"sg-a"}},
		{name: "sorted and trimmed", annotation: " sg-b , sg-a ", want: []string{"sg-a", "sg-b"}},
		{name: "deduplicated", annotation: "sg-a,sg-a", want: []string{"sg-a"}},
		{name: "empty entries dropped", annotation: "sg-a,,sg-b", want: []string{"sg-a", "sg-b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParsePodSecurityGroups(tc.annotation)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParsePodSecurityGroups(%q) = %v, want %v", tc.annotation, got, tc.want)
			}
		})
	}
}

func TestParsePodNetworkAttachments(t *testing.T) {
	t.Run("empty annotation yields no attachment", func(t *testing.T) {
		got, err := ParsePodNetworkAttachments("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v, want no attachment", got)
		}
	})

	t.Run("reads every field of every entry", func(t *testing.T) {
		got, err := ParsePodNetworkAttachments(`[
			{"interface": "eth1", "subnet": "db"},
			{"interface": "eth2", "subnet": "mgmt", "address": "10.17.0.9", "securityGroups": ["sg-b"]},
			{"interface": "eth3", "l2Network": "lab-net"}
		]`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{
			{Interface: "eth1", Subnet: "db"},
			{Interface: "eth2", Subnet: "mgmt", Address: "10.17.0.9", SecurityGroups: []string{"sg-b"}},
			{Interface: "eth3", L2Network: "lab-net"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("rejects malformed JSON", func(t *testing.T) {
		if _, err := ParsePodNetworkAttachments(`[{"interface": "eth1"`); err == nil {
			t.Fatal("expected an error for truncated JSON")
		}
	})

	t.Run("rejects a JSON object instead of a list", func(t *testing.T) {
		if _, err := ParsePodNetworkAttachments(`{"interface": "eth1", "subnet": "db"}`); err == nil {
			t.Fatal("expected an error for a non-list value")
		}
	})

	t.Run("rejects an unknown field", func(t *testing.T) {
		_, err := ParsePodNetworkAttachments(`[{"interface": "eth1", "subnets": "db"}]`)
		if err == nil {
			t.Fatal("expected an error for an unknown field")
		}
		if !strings.Contains(err.Error(), "subnets") {
			t.Fatalf("error should name the unknown field, got %v", err)
		}
	})

	t.Run("rejects trailing content", func(t *testing.T) {
		if _, err := ParsePodNetworkAttachments(`[] []`); err == nil {
			t.Fatal("expected an error for trailing content")
		}
	})
}

func TestValidatePodNetworkAttachments(t *testing.T) {
	path := field.NewPath("metadata", "annotations").Key(PodAnnotationNetworks)

	cases := []struct {
		name        string
		attachments []PodNetworkAttachment
		wantErr     string
	}{
		{
			name:        "accepts a minimal entry",
			attachments: []PodNetworkAttachment{{Interface: "eth1", Subnet: "db"}},
		},
		{
			name: "accepts the maximum number of security groups",
			attachments: []PodNetworkAttachment{
				{Interface: "eth1", Subnet: "db", SecurityGroups: []string{"sg-a", "sg-b"}},
			},
		},
		{
			name:        "rejects a missing interface",
			attachments: []PodNetworkAttachment{{Subnet: "db"}},
			wantErr:     "interface",
		},
		{
			name:        "rejects the primary interface",
			attachments: []PodNetworkAttachment{{Interface: PodPrimaryInterfaceName, Subnet: "db"}},
			wantErr:     PodPrimaryInterfaceName,
		},
		{
			name: "rejects a duplicated interface",
			attachments: []PodNetworkAttachment{
				{Interface: "eth1", Subnet: "db"},
				{Interface: "eth1", Subnet: "mgmt"},
			},
			wantErr: "Duplicate",
		},
		{
			name:        "rejects an interface name longer than a veth name can hold",
			attachments: []PodNetworkAttachment{{Interface: strings.Repeat("e", PodInterfaceNameMaxLen+1), Subnet: "db"}},
			wantErr:     "interface",
		},
		{
			name:        "accepts an interface name at the limit",
			attachments: []PodNetworkAttachment{{Interface: strings.Repeat("e", PodInterfaceNameMaxLen), Subnet: "db"}},
		},
		{
			name:        "rejects an interface name that is not a DNS label",
			attachments: []PodNetworkAttachment{{Interface: "eth_1", Subnet: "db"}},
			wantErr:     "interface",
		},
		{
			name:        "accepts an entry that names an l2Network",
			attachments: []PodNetworkAttachment{{Interface: "eth1", L2Network: "lab-net"}},
		},
		{
			name:        "rejects an entry that names neither a subnet nor an l2Network",
			attachments: []PodNetworkAttachment{{Interface: "eth1"}},
			wantErr:     "needs a subnet or an l2Network",
		},
		{
			name:        "rejects an entry that names both a subnet and an l2Network",
			attachments: []PodNetworkAttachment{{Interface: "eth1", Subnet: "db", L2Network: "lab-net"}},
			wantErr:     "not both",
		},
		{
			name:        "rejects an l2Network name that is not a DNS subdomain",
			attachments: []PodNetworkAttachment{{Interface: "eth1", L2Network: "Lab_Net"}},
			wantErr:     "l2Network",
		},
		{
			name:        "rejects an address that is not an IP",
			attachments: []PodNetworkAttachment{{Interface: "eth1", Subnet: "db", Address: "not-an-ip"}},
			wantErr:     "address",
		},
		{
			name: "rejects more security groups than a NIC can hold",
			attachments: []PodNetworkAttachment{
				{Interface: "eth1", Subnet: "db", SecurityGroups: []string{"sg-a", "sg-b", "sg-c"}},
			},
			wantErr: "at most",
		},
		{
			name: "rejects a duplicated security group",
			attachments: []PodNetworkAttachment{
				{Interface: "eth1", Subnet: "db", SecurityGroups: []string{"sg-a", "sg-a"}},
			},
			wantErr: "Duplicate",
		},
		{
			name: "rejects an empty security group name",
			attachments: []PodNetworkAttachment{
				{Interface: "eth1", Subnet: "db", SecurityGroups: []string{""}},
			},
			wantErr: "securityGroups",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := ValidatePodNetworkAttachments(path, tc.attachments)
			if tc.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("expected no error, got %v", errs)
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(errs.ToAggregate().Error(), tc.wantErr) {
				t.Fatalf("error %v should mention %q", errs, tc.wantErr)
			}
		})
	}
}

func TestPodNetworkAttachments(t *testing.T) {
	t.Run("puts the primary NIC first", func(t *testing.T) {
		got, err := PodNetworkAttachments(map[string]string{
			PodAnnotationSubnet:         "web",
			PodAnnotationAddress:        "10.16.1.5",
			PodAnnotationSecurityGroups: "sg-a",
			PodAnnotationNetworks:       `[{"interface": "eth1", "subnet": "db"}]`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{
			{Interface: PodPrimaryInterfaceName, Subnet: "web", Address: "10.16.1.5", SecurityGroups: []string{"sg-a"}},
			{Interface: "eth1", Subnet: "db"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("falls back to the default subnet for the primary NIC only", func(t *testing.T) {
		got, err := PodNetworkAttachments(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{{Interface: PodPrimaryInterfaceName, Subnet: PodDefaultSubnetName}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("reports an invalid extra NIC", func(t *testing.T) {
		_, err := PodNetworkAttachments(map[string]string{
			PodAnnotationNetworks: `[{"interface": "eth0", "subnet": "db"}]`,
		})
		if err == nil {
			t.Fatal("expected an error for an entry naming the primary NIC")
		}
	})
}
