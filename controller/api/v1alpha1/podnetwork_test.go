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
			{"interface": "eth3", "l2Network": "lab-net"},
			{"interface": "ext0", "elasticIP": "public-web"}
		]`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{
			{Interface: "eth1", Subnet: "db"},
			{Interface: "eth2", Subnet: "mgmt", Address: "10.17.0.9", SecurityGroups: []string{"sg-b"}},
			{Interface: "eth3", L2Network: "lab-net"},
			{Interface: "ext0", ElasticIP: "public-web"},
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
			name:        "accepts the primary interface",
			attachments: []PodNetworkAttachment{{Interface: PodPrimaryInterfaceName, Subnet: "db"}},
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
			name:        "rejects an entry that names no network",
			attachments: []PodNetworkAttachment{{Interface: "eth1"}},
			wantErr:     "needs a subnet, an l2Network or an elasticIP",
		},
		{
			name:        "rejects an entry that names both a subnet and an l2Network",
			attachments: []PodNetworkAttachment{{Interface: "eth1", Subnet: "db", L2Network: "lab-net"}},
			wantErr:     "exactly one of",
		},
		{
			name:        "rejects an entry that names both a subnet and an elasticIP",
			attachments: []PodNetworkAttachment{{Interface: "eth1", Subnet: "db", ElasticIP: "public-web"}},
			wantErr:     "exactly one of",
		},
		{
			name:        "rejects an entry that names both an l2Network and an elasticIP",
			attachments: []PodNetworkAttachment{{Interface: "eth1", L2Network: "lab-net", ElasticIP: "public-web"}},
			wantErr:     "exactly one of",
		},
		{
			name:        "rejects an l2Network name that is not a DNS subdomain",
			attachments: []PodNetworkAttachment{{Interface: "eth1", L2Network: "Lab_Net"}},
			wantErr:     "l2Network",
		},
		{
			name:        "accepts an entry that names an elasticIP",
			attachments: []PodNetworkAttachment{{Interface: "ext0", ElasticIP: "public-web"}},
		},
		{
			name:        "accepts the primary interface on an elasticIP",
			attachments: []PodNetworkAttachment{{Interface: PodPrimaryInterfaceName, ElasticIP: "public-web"}},
		},
		{
			name:        "rejects an elasticIP in another namespace",
			attachments: []PodNetworkAttachment{{Interface: "ext0", ElasticIP: "other/public-web"}},
			wantErr:     "elasticIP",
		},
		{
			name:        "rejects an address on an elasticIP entry",
			attachments: []PodNetworkAttachment{{Interface: "ext0", ElasticIP: "public-web", Address: "203.0.113.10"}},
			wantErr:     "address",
		},
		{
			name:        "rejects security groups on an elasticIP entry",
			attachments: []PodNetworkAttachment{{Interface: "ext0", ElasticIP: "public-web", SecurityGroups: []string{"sg-a"}}},
			wantErr:     "securityGroups",
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

	t.Run("keeps an empty subnet annotation on the default subnet", func(t *testing.T) {
		got, err := PodNetworkAttachments(map[string]string{PodAnnotationSubnet: ""})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{{Interface: PodPrimaryInterfaceName, Subnet: PodDefaultSubnetName}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("reads the primary NIC from a networks entry and puts it first", func(t *testing.T) {
		got, err := PodNetworkAttachments(map[string]string{
			PodAnnotationNetworks: `[{"interface": "eth1", "subnet": "db"}, {"interface": "eth0", "l2Network": "lab-net"}]`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{
			{Interface: PodPrimaryInterfaceName, L2Network: "lab-net"},
			{Interface: "eth1", Subnet: "db"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("does not add the default subnet when a networks entry describes the primary NIC", func(t *testing.T) {
		got, err := PodNetworkAttachments(map[string]string{
			PodAnnotationNetworks: `[{"interface": "eth0", "elasticIP": "public-web"}]`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{{Interface: PodPrimaryInterfaceName, ElasticIP: "public-web"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("does not add the default subnet when the elastic-ip annotation describes the primary NIC", func(t *testing.T) {
		got, err := PodNetworkAttachments(map[string]string{
			PodAnnotationElasticIP: "public-web",
			PodAnnotationNetworks:  `[{"interface": "eth1", "subnet": "db"}]`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []PodNetworkAttachment{
			{Interface: PodPrimaryInterfaceName, ElasticIP: "public-web"},
			{Interface: "eth1", Subnet: "db"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	rejects := []struct {
		name        string
		annotations map[string]string
		wantErr     []string
	}{
		{
			name:        "an unreadable networks annotation",
			annotations: map[string]string{PodAnnotationNetworks: `eth1=db`},
			wantErr:     []string{PodAnnotationNetworks},
		},
		{
			name:        "an invalid networks entry",
			annotations: map[string]string{PodAnnotationNetworks: `[{"interface": "eth1"}]`},
			wantErr:     []string{PodAnnotationNetworks},
		},
		{
			name: "a subnet annotation next to a networks entry for the primary NIC",
			annotations: map[string]string{
				PodAnnotationSubnet:   "web",
				PodAnnotationNetworks: `[{"interface": "eth0", "subnet": "db"}]`,
			},
			wantErr: []string{PodAnnotationSubnet, PodPrimaryInterfaceName},
		},
		{
			name: "an empty subnet annotation next to a networks entry for the primary NIC",
			annotations: map[string]string{
				PodAnnotationSubnet:   "",
				PodAnnotationNetworks: `[{"interface": "eth0", "subnet": "db"}]`,
			},
			wantErr: []string{PodAnnotationSubnet},
		},
		{
			name: "an address annotation next to a networks entry for the primary NIC",
			annotations: map[string]string{
				PodAnnotationAddress:  "10.16.1.5",
				PodAnnotationNetworks: `[{"interface": "eth0", "subnet": "db"}]`,
			},
			wantErr: []string{PodAnnotationAddress},
		},
		{
			name: "a security-groups annotation next to a networks entry for the primary NIC",
			annotations: map[string]string{
				PodAnnotationSecurityGroups: "sg-a",
				PodAnnotationNetworks:       `[{"interface": "eth0", "subnet": "db"}]`,
			},
			wantErr: []string{PodAnnotationSecurityGroups},
		},
		{
			name: "an elastic-ip annotation next to a networks entry for the primary NIC",
			annotations: map[string]string{
				PodAnnotationElasticIP: "public-web",
				PodAnnotationNetworks:  `[{"interface": "eth0", "subnet": "db"}]`,
			},
			wantErr: []string{PodAnnotationElasticIP},
		},
		{
			name: "an elastic-ip annotation next to a subnet annotation",
			annotations: map[string]string{
				PodAnnotationElasticIP: "public-web",
				PodAnnotationSubnet:    "web",
			},
			wantErr: []string{PodAnnotationSubnet, PodAnnotationElasticIP},
		},
		{
			name: "an elastic-ip annotation next to an address annotation",
			annotations: map[string]string{
				PodAnnotationElasticIP: "public-web",
				PodAnnotationAddress:   "203.0.113.10",
			},
			wantErr: []string{PodAnnotationAddress},
		},
		{
			name: "an elastic-ip annotation next to a security-groups annotation",
			annotations: map[string]string{
				PodAnnotationElasticIP:      "public-web",
				PodAnnotationSecurityGroups: "sg-a",
			},
			wantErr: []string{PodAnnotationSecurityGroups},
		},
		{
			name:        "an empty elastic-ip annotation",
			annotations: map[string]string{PodAnnotationElasticIP: ""},
			wantErr:     []string{PodAnnotationElasticIP},
		},
		{
			name:        "an elastic-ip annotation that names an ElasticIP in another namespace",
			annotations: map[string]string{PodAnnotationElasticIP: "other/public-web"},
			wantErr:     []string{PodAnnotationElasticIP},
		},
		{
			name: "one ElasticIP on the primary NIC and on an extra NIC",
			annotations: map[string]string{
				PodAnnotationElasticIP: "public-web",
				PodAnnotationNetworks:  `[{"interface": "ext0", "elasticIP": "public-web"}]`,
			},
			wantErr: []string{"Duplicate", "public-web"},
		},
		{
			name: "one ElasticIP on two extra NICs",
			annotations: map[string]string{
				PodAnnotationNetworks: `[{"interface": "ext0", "elasticIP": "public-web"}, {"interface": "ext1", "elasticIP": "public-web"}]`,
			},
			wantErr: []string{"Duplicate", "public-web"},
		},
	}
	for _, tc := range rejects {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			_, err := PodNetworkAttachments(tc.annotations)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %v should mention %q", err, want)
				}
			}
		})
	}
}

func TestResolvePodNetworkAttachments(t *testing.T) {
	t.Run("points every NIC at the annotation that describes it", func(t *testing.T) {
		got, errs := ResolvePodNetworkAttachments(map[string]string{
			PodAnnotationNetworks: `[{"interface": "eth1", "subnet": "db"}, {"interface": "eth0", "subnet": "web"}]`,
		})
		if len(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		want := []ResolvedPodNetworkAttachment{
			{
				PodNetworkAttachment: PodNetworkAttachment{Interface: PodPrimaryInterfaceName, Subnet: "web"},
				Source:               PodNetworkAttachmentSource{Annotation: PodAnnotationNetworks, Index: 1},
			},
			{
				PodNetworkAttachment: PodNetworkAttachment{Interface: "eth1", Subnet: "db"},
				Source:               PodNetworkAttachmentSource{Annotation: PodAnnotationNetworks, Index: 0},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	sources := []struct {
		name        string
		annotations map[string]string
		want        PodNetworkAttachmentSource
	}{
		{
			name:        "the subnet annotation",
			annotations: map[string]string{PodAnnotationSubnet: "web"},
			want:        PodNetworkAttachmentSource{Annotation: PodAnnotationSubnet},
		},
		{
			name:        "the default subnet",
			annotations: nil,
			want:        PodNetworkAttachmentSource{Annotation: PodAnnotationSubnet},
		},
		{
			name:        "the elastic-ip annotation",
			annotations: map[string]string{PodAnnotationElasticIP: "public-web"},
			want:        PodNetworkAttachmentSource{Annotation: PodAnnotationElasticIP},
		},
	}
	for _, tc := range sources {
		t.Run("sources the primary NIC from "+tc.name, func(t *testing.T) {
			got, errs := ResolvePodNetworkAttachments(tc.annotations)
			if len(errs) != 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			if got[0].Source != tc.want {
				t.Fatalf("got source %+v, want %+v", got[0].Source, tc.want)
			}
		})
	}

	t.Run("reports every problem at the annotation it comes from", func(t *testing.T) {
		_, errs := ResolvePodNetworkAttachments(map[string]string{
			PodAnnotationSubnet:   "web",
			PodAnnotationAddress:  "10.16.1.5",
			PodAnnotationNetworks: `[{"interface": "eth0", "elasticIP": "public-web", "address": "203.0.113.10"}]`,
		})
		annotations := field.NewPath("metadata", "annotations")
		wantFields := []string{
			annotations.Key(PodAnnotationSubnet).String(),
			annotations.Key(PodAnnotationAddress).String(),
			annotations.Key(PodAnnotationNetworks).Index(0).Child("address").String(),
		}
		for _, want := range wantFields {
			found := false
			for _, err := range errs {
				if err.Field == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("errors %v should include one at %s", errs, want)
			}
		}
	})
}

func TestPodPrimaryNetworkAttachment(t *testing.T) {
	t.Run("reads the primary NIC from a networks entry", func(t *testing.T) {
		got, err := PodPrimaryNetworkAttachment(map[string]string{
			PodAnnotationNetworks: `[{"interface": "eth1", "subnet": "db"}, {"interface": "eth0", "elasticIP": "public-web"}]`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := PodNetworkAttachment{Interface: PodPrimaryInterfaceName, ElasticIP: "public-web"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("fails when the annotations conflict", func(t *testing.T) {
		_, err := PodPrimaryNetworkAttachment(map[string]string{
			PodAnnotationSubnet:    "web",
			PodAnnotationElasticIP: "public-web",
		})
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}
