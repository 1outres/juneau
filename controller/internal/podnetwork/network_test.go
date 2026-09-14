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

package podnetwork

import (
	"context"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func TestReferenceValidate(t *testing.T) {
	cases := []struct {
		name    string
		ref     Reference
		wantErr bool
	}{
		{name: "a Subnet alone is fine", ref: Reference{Subnet: "web"}},
		{name: "an L2Network alone is fine", ref: Reference{L2Network: "lab"}},
		{name: "an ElasticIP alone is fine", ref: Reference{ElasticIP: "web-eip", Namespace: "default"}},
		{name: "neither is an error", ref: Reference{}, wantErr: true},
		{name: "both is an error", ref: Reference{Subnet: "web", L2Network: "lab"}, wantErr: true},
		{name: "an ElasticIP next to a Subnet is an error", ref: Reference{Subnet: "web", ElasticIP: "web-eip", Namespace: "default"}, wantErr: true},
		{name: "an ElasticIP next to an L2Network is an error", ref: Reference{L2Network: "lab", ElasticIP: "web-eip", Namespace: "default"}, wantErr: true},
		{name: "an ElasticIP with no namespace to look in is an error", ref: Reference{ElasticIP: "web-eip"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ref.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestReferenceNaming(t *testing.T) {
	subnet := Reference{Subnet: "web"}
	if got, want := subnet.Kind(), KindSubnet; got != want {
		t.Fatalf("Kind() = %v, want %v", got, want)
	}
	if got, want := subnet.Name(), "web"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if got, want := subnet.AllocationPoolName(), "subnet-ip-web"; got != want {
		t.Fatalf("AllocationPoolName() = %q, want %q", got, want)
	}
	if got, want := subnet.String(), `Subnet "web"`; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}

	l2 := Reference{L2Network: "lab"}
	if got, want := l2.Kind(), KindL2Network; got != want {
		t.Fatalf("Kind() = %v, want %v", got, want)
	}
	if got, want := l2.AllocationPoolName(), "l2network-ip-lab"; got != want {
		t.Fatalf("AllocationPoolName() = %q, want %q", got, want)
	}
	if got, want := l2.String(), `L2Network "lab"`; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}

	elasticIP := Reference{ElasticIP: "web-eip", Namespace: "shop"}
	if got, want := elasticIP.Kind(), KindElasticIP; got != want {
		t.Fatalf("Kind() = %v, want %v", got, want)
	}
	if got, want := elasticIP.Name(), "web-eip"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if got, want := elasticIP.String(), `ElasticIP "shop/web-eip"`; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if elasticIP.HasAllocationPool() {
		t.Fatal("an ElasticIP draws its address from no AllocationPool")
	}
	if !subnet.HasAllocationPool() || !l2.HasAllocationPool() {
		t.Fatal("a Subnet and an L2Network hand addresses out of an AllocationPool")
	}
}

func TestReferenceConstructors(t *testing.T) {
	networkInterface := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web.eth0", Namespace: "shop"},
		Spec:       juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "web-eip"},
	}
	if got, want := InterfaceReference(networkInterface), (Reference{ElasticIP: "web-eip", Namespace: "shop"}); got != want {
		t.Fatalf("InterfaceReference() = %+v, want %+v", got, want)
	}

	attachment := juneauv1alpha1.PodNetworkAttachment{Interface: "ext0", ElasticIP: "web-eip"}
	if got, want := AttachmentReference("shop", attachment), (Reference{ElasticIP: "web-eip", Namespace: "shop"}); got != want {
		t.Fatalf("AttachmentReference() = %+v, want %+v", got, want)
	}
}

func TestResolve(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	subnet := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
		Spec:       juneauv1alpha1.SubnetSpec{Vpc: "prod", CIDR: "10.0.1.0/24"},
		Status:     juneauv1alpha1.SubnetStatus{Gateway: "10.0.1.1"},
	}
	routed := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab"},
		Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "prod", CIDR: "10.0.2.0/24"},
		Status:     juneauv1alpha1.L2NetworkStatus{Gateway: "10.0.2.1", MTU: 1450},
	}
	plain := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "plain"},
		Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "prod"},
		Status:     juneauv1alpha1.L2NetworkStatus{MTU: 1450},
	}
	numbered := &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "internet"},
		Spec:       juneauv1alpha1.ExternalNetworkSpec{Type: juneauv1alpha1.ExternalNetworkTypeBGP, AddressPools: []string{"public"}},
		Status:     juneauv1alpha1.ExternalNetworkStatus{NetworkID: 4100},
	}
	unnumbered := &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "fresh"},
		Spec:       juneauv1alpha1.ExternalNetworkSpec{Type: juneauv1alpha1.ExternalNetworkTypeBGP, AddressPools: []string{"fresh"}},
	}
	attached := &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Name: "web-eip", Namespace: "shop"},
		Spec:       juneauv1alpha1.ElasticIPSpec{ExternalNetwork: "internet"},
		Status: juneauv1alpha1.ElasticIPStatus{
			Phase:   juneauv1alpha1.ElasticIPPhaseAttached,
			Address: "203.0.113.10",
			Attachment: &juneauv1alpha1.ElasticIPStatusAttachment{
				Kind: juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface,
				Name: "web.eth0",
			},
		},
	}
	pending := &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Name: "pending-eip", Namespace: "shop"},
		Spec:       juneauv1alpha1.ElasticIPSpec{ExternalNetwork: "internet"},
		Status:     juneauv1alpha1.ElasticIPStatus{Phase: juneauv1alpha1.ElasticIPPhasePending},
	}
	onFresh := &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Name: "fresh-eip", Namespace: "shop"},
		Spec:       juneauv1alpha1.ElasticIPSpec{ExternalNetwork: "fresh"},
		Status:     juneauv1alpha1.ElasticIPStatus{Phase: juneauv1alpha1.ElasticIPPhaseAvailable, Address: "198.51.100.7"},
	}
	orphan := &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-eip", Namespace: "shop"},
		Spec:       juneauv1alpha1.ElasticIPSpec{ExternalNetwork: "gone"},
		Status:     juneauv1alpha1.ElasticIPStatus{Address: "198.51.100.8"},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(subnet, routed, plain, numbered, unnumbered, attached, pending, onFresh, orphan).
		Build()

	t.Run("reads a Subnet", func(t *testing.T) {
		network, err := Resolve(context.Background(), reader, Reference{Subnet: "web"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if network.Vpc != "prod" || network.CIDR != "10.0.1.0/24" || network.Gateway != "10.0.1.1" {
			t.Fatalf("got %+v", network)
		}
		if !network.AllocatesAddresses() {
			t.Fatal("a Subnet always hands out addresses")
		}
		if got, want := network.AllocationPoolName(), "subnet-ip-web"; got != want {
			t.Fatalf("AllocationPoolName() = %q, want %q", got, want)
		}
	})

	t.Run("reads an L2Network with a CIDR", func(t *testing.T) {
		network, err := Resolve(context.Background(), reader, Reference{L2Network: "lab"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if network.Vpc != "prod" || network.CIDR != "10.0.2.0/24" || network.Gateway != "10.0.2.1" {
			t.Fatalf("got %+v", network)
		}
		if !network.AllocatesAddresses() {
			t.Fatal("an L2Network with a CIDR hands out addresses")
		}
	})

	t.Run("reports an L2Network without a CIDR as handing out nothing", func(t *testing.T) {
		network, err := Resolve(context.Background(), reader, Reference{L2Network: "plain"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if network.AllocatesAddresses() {
			t.Fatal("an L2Network without a CIDR hands out no address")
		}
	})

	t.Run("passes a missing object through as NotFound", func(t *testing.T) {
		_, err := Resolve(context.Background(), reader, Reference{L2Network: "gone"})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("expected a NotFound error, got %v", err)
		}
	})

	t.Run("reports a missing object as nothing when it is optional", func(t *testing.T) {
		network, err := ResolveOptional(context.Background(), reader, Reference{Subnet: "gone"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if network != nil {
			t.Fatalf("got %+v, want no network", network)
		}
	})

	t.Run("rejects a reference that names nothing", func(t *testing.T) {
		if _, err := Resolve(context.Background(), reader, Reference{}); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("reads an ElasticIP together with its ExternalNetwork", func(t *testing.T) {
		network, err := Resolve(context.Background(), reader, Reference{ElasticIP: "web-eip", Namespace: "shop"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := ElasticIPBinding{
			Address:         "203.0.113.10",
			Attachment:      attached.Status.Attachment,
			ExternalNetwork: "internet",
			NetworkID:       4100,
		}
		if network.ElasticIP == nil || !reflect.DeepEqual(*network.ElasticIP, want) {
			t.Fatalf("ElasticIP = %+v, want %+v", network.ElasticIP, want)
		}
		if network.Vpc != "" || network.AllocatesAddresses() {
			t.Fatalf("an ElasticIP joins no Vpc and allocates nothing, got %+v", network)
		}
		if got := network.WaitingFor(); got != "" {
			t.Fatalf("WaitingFor() = %q, want nothing", got)
		}
		if !network.ElasticIP.HeldBy("web.eth0") || network.ElasticIP.HeldBy("other.eth0") {
			t.Fatal("HeldBy has to name only the NetworkInterface in status.attachment")
		}
	})

	t.Run("leaves the ElasticIP binding out for a Subnet", func(t *testing.T) {
		network, err := Resolve(context.Background(), reader, Reference{Subnet: "web"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if network.ElasticIP != nil {
			t.Fatalf("ElasticIP = %+v, want none", network.ElasticIP)
		}
		if got := network.WaitingFor(); got != "" {
			t.Fatalf("WaitingFor() = %q, want nothing", got)
		}
	})

	t.Run("waits for an ElasticIP that has no address yet", func(t *testing.T) {
		network, err := Resolve(context.Background(), reader, Reference{ElasticIP: "pending-eip", Namespace: "shop"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, want := network.WaitingFor(), `ElasticIP "shop/pending-eip" has no address yet`; got != want {
			t.Fatalf("WaitingFor() = %q, want %q", got, want)
		}
	})

	t.Run("waits for an ExternalNetwork that has no network ID yet", func(t *testing.T) {
		network, err := Resolve(context.Background(), reader, Reference{ElasticIP: "fresh-eip", Namespace: "shop"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, want := network.WaitingFor(), `ExternalNetwork "fresh" of ElasticIP "shop/fresh-eip" has no network ID yet`; got != want {
			t.Fatalf("WaitingFor() = %q, want %q", got, want)
		}
	})

	t.Run("passes a missing ElasticIP through as NotFound", func(t *testing.T) {
		_, err := Resolve(context.Background(), reader, Reference{ElasticIP: "web-eip", Namespace: "elsewhere"})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("expected a NotFound error, got %v", err)
		}
	})

	t.Run("passes the missing ExternalNetwork of an ElasticIP through as NotFound", func(t *testing.T) {
		_, err := Resolve(context.Background(), reader, Reference{ElasticIP: "orphan-eip", Namespace: "shop"})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("expected a NotFound error, got %v", err)
		}
		if !strings.Contains(err.Error(), `ElasticIP "shop/orphan-eip"`) {
			t.Fatalf("the error does not say which ElasticIP it was read for: %v", err)
		}
	})
}

func TestL2NetworkGatewayAddress(t *testing.T) {
	tests := []struct {
		name    string
		l2      juneauv1alpha1.L2Network
		want    string
		wantErr bool
	}{
		{
			name: "no gateway",
			l2:   juneauv1alpha1.L2Network{Spec: juneauv1alpha1.L2NetworkSpec{CIDR: "10.0.0.0/24"}},
			want: "",
		},
		{
			name: "the first address of the prefix by default",
			l2: juneauv1alpha1.L2Network{Spec: juneauv1alpha1.L2NetworkSpec{
				CIDR:    "10.0.0.0/24",
				Gateway: &juneauv1alpha1.L2NetworkGateway{},
			}},
			want: "10.0.0.1",
		},
		{
			name: "the address the user pinned",
			l2: juneauv1alpha1.L2Network{Spec: juneauv1alpha1.L2NetworkSpec{
				CIDR:    "10.0.0.0/24",
				Gateway: &juneauv1alpha1.L2NetworkGateway{Address: "10.0.0.254"},
			}},
			want: "10.0.0.254",
		},
		{
			name: "a gateway with no prefix to take an address from",
			l2: juneauv1alpha1.L2Network{Spec: juneauv1alpha1.L2NetworkSpec{
				Gateway: &juneauv1alpha1.L2NetworkGateway{},
			}},
			wantErr: true,
		},
		{
			name: "a prefix too narrow to hold a gateway",
			l2: juneauv1alpha1.L2Network{Spec: juneauv1alpha1.L2NetworkSpec{
				CIDR:    "10.0.0.0/32",
				Gateway: &juneauv1alpha1.L2NetworkGateway{},
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := L2NetworkGatewayAddress(&tt.l2)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
