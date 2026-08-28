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
		{name: "neither is an error", ref: Reference{}, wantErr: true},
		{name: "both is an error", ref: Reference{Subnet: "web", L2Network: "lab"}, wantErr: true},
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
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(subnet, routed, plain).Build()

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
}
