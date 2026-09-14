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

package controller

import (
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func TestDecideElasticIPUse(t *testing.T) {
	base := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	nic := func(name, node string, age time.Duration, deleting bool) juneauv1alpha1.NetworkInterface {
		networkInterface := juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				Namespace:         "default",
				CreationTimestamp: metav1.NewTime(base.Add(-age)),
			},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{NodeName: node, ElasticIP: "web-eip"},
		}
		if deleting {
			now := metav1.NewTime(base)
			networkInterface.DeletionTimestamp = &now
		}
		return networkInterface
	}
	natUse := func(name, node string) juneauv1alpha1.ElasticIPAttachment {
		return juneauv1alpha1.ElasticIPAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Status:     juneauv1alpha1.ElasticIPAttachmentStatus{NodeName: node},
		}
	}
	heldBy := func(kind juneauv1alpha1.ElasticIPStatusAttachmentKind, name string) *juneauv1alpha1.ElasticIPStatusAttachment {
		return &juneauv1alpha1.ElasticIPStatusAttachment{Kind: kind, Name: name}
	}
	direct := juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface
	nat := juneauv1alpha1.ElasticIPStatusAttachmentKindElasticIPAttachment

	cases := []struct {
		name        string
		previous    *juneauv1alpha1.ElasticIPStatusAttachment
		attachments []juneauv1alpha1.ElasticIPAttachment
		interfaces  []juneauv1alpha1.NetworkInterface

		wantAttachment *juneauv1alpha1.ElasticIPStatusAttachment
		wantNode       string
		wantConflict   string
		wantWaiting    string
	}{
		{
			name: "nothing uses an ElasticIP nobody names",
		},
		{
			name:           "one ElasticIPAttachment uses it from the node it is on",
			attachments:    []juneauv1alpha1.ElasticIPAttachment{natUse("nat-a", "node-a")},
			wantAttachment: heldBy(nat, "nat-a"),
			wantNode:       "node-a",
		},
		{
			name:         "two ElasticIPAttachments conflict",
			attachments:  []juneauv1alpha1.ElasticIPAttachment{natUse("nat-a", "node-a"), natUse("nat-b", "node-b")},
			wantConflict: "multiple ElasticIPAttachments",
		},
		{
			name:         "an ElasticIPAttachment and a NetworkInterface conflict",
			attachments:  []juneauv1alpha1.ElasticIPAttachment{natUse("nat-a", "node-a")},
			interfaces:   []juneauv1alpha1.NetworkInterface{nic("web-0.eth0", "node-b", time.Minute, false)},
			wantConflict: `ElasticIPAttachment "nat-a" and NetworkInterface "web-0.eth0"`,
		},
		{
			name:         "a NetworkInterface on its way out still conflicts with an ElasticIPAttachment",
			attachments:  []juneauv1alpha1.ElasticIPAttachment{natUse("nat-a", "node-a")},
			interfaces:   []juneauv1alpha1.NetworkInterface{nic("web-0.eth0", "node-b", time.Minute, true)},
			wantConflict: `NetworkInterface "web-0.eth0"`,
		},
		{
			name:           "the only NetworkInterface that names it carries it from its node",
			interfaces:     []juneauv1alpha1.NetworkInterface{nic("web-0.eth0", "node-b", time.Minute, false)},
			wantAttachment: heldBy(direct, "web-0.eth0"),
			wantNode:       "node-b",
		},
		{
			name: "the oldest of two new NetworkInterfaces carries it",
			interfaces: []juneauv1alpha1.NetworkInterface{
				nic("a-young.eth0", "node-a", time.Second, false),
				nic("z-old.eth0", "node-z", time.Hour, false),
			},
			wantAttachment: heldBy(direct, "z-old.eth0"),
			wantNode:       "node-z",
		},
		{
			name: "the name decides between two NetworkInterfaces made in the same second",
			interfaces: []juneauv1alpha1.NetworkInterface{
				nic("web-1.eth0", "node-b", time.Minute, false),
				nic("web-0.eth0", "node-a", time.Minute, false),
			},
			wantAttachment: heldBy(direct, "web-0.eth0"),
			wantNode:       "node-a",
		},
		{
			name:     "the holder keeps it although an older NetworkInterface names it too",
			previous: heldBy(direct, "web-1.eth0"),
			interfaces: []juneauv1alpha1.NetworkInterface{
				nic("web-0.eth0", "node-a", time.Hour, false),
				nic("web-1.eth0", "node-b", time.Minute, false),
			},
			wantAttachment: heldBy(direct, "web-1.eth0"),
			wantNode:       "node-b",
		},
		{
			name:     "a holder being deleted keeps it until it is gone",
			previous: heldBy(direct, "vm-old.eth0"),
			interfaces: []juneauv1alpha1.NetworkInterface{
				nic("vm-old.eth0", "node-a", time.Hour, true),
				nic("vm-new.eth0", "node-b", time.Second, false),
			},
			wantAttachment: heldBy(direct, "vm-old.eth0"),
			wantNode:       "node-a",
		},
		{
			name:     "a new NetworkInterface takes it once the holder is gone",
			previous: heldBy(direct, "vm-old.eth0"),
			interfaces: []juneauv1alpha1.NetworkInterface{
				nic("vm-new.eth0", "node-b", time.Second, false),
			},
			wantAttachment: heldBy(direct, "vm-new.eth0"),
			wantNode:       "node-b",
		},
		{
			name: "nobody takes it while a NetworkInterface that may still hold it is being deleted",
			interfaces: []juneauv1alpha1.NetworkInterface{
				nic("vm-old.eth0", "node-a", time.Hour, true),
				nic("vm-new.eth0", "node-b", time.Second, false),
			},
			wantWaiting: `NetworkInterface "vm-old.eth0"`,
		},
		{
			name:     "an ElasticIPAttachment it was attached to does not make a NetworkInterface wait",
			previous: heldBy(nat, "nat-a"),
			interfaces: []juneauv1alpha1.NetworkInterface{
				nic("web-0.eth0", "node-a", time.Minute, false),
			},
			wantAttachment: heldBy(direct, "web-0.eth0"),
			wantNode:       "node-a",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideElasticIPUse(tc.previous, tc.attachments, tc.interfaces)
			if !reflect.DeepEqual(got.attachment, tc.wantAttachment) {
				t.Errorf("attachment = %+v, want %+v", got.attachment, tc.wantAttachment)
			}
			if got.nodeName != tc.wantNode {
				t.Errorf("nodeName = %q, want %q", got.nodeName, tc.wantNode)
			}
			if !containsOrBothEmpty(got.conflict, tc.wantConflict) {
				t.Errorf("conflict = %q, want it to mention %q", got.conflict, tc.wantConflict)
			}
			if !containsOrBothEmpty(got.waitingFor, tc.wantWaiting) {
				t.Errorf("waitingFor = %q, want it to mention %q", got.waitingFor, tc.wantWaiting)
			}
		})
	}
}

func containsOrBothEmpty(got, want string) bool {
	if want == "" {
		return got == ""
	}
	return strings.Contains(got, want)
}

func TestMapNetworkInterfaceToElasticIP(t *testing.T) {
	onElasticIP := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0.eth0", Namespace: "shop"},
		Spec:       juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "web-eip"},
	}
	want := []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: "shop", Name: "web-eip"}}}
	if got := mapNetworkInterfaceToElasticIP(t.Context(), onElasticIP); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	onSubnet := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0.eth1", Namespace: "shop"},
		Spec:       juneauv1alpha1.NetworkInterfaceSpec{Subnet: "web"},
	}
	if got := mapNetworkInterfaceToElasticIP(t.Context(), onSubnet); len(got) != 0 {
		t.Fatalf("a NetworkInterface on a Subnet woke %+v", got)
	}
}
