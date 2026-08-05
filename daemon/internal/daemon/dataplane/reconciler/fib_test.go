package reconciler

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func newFibFixture(t *testing.T, objects ...runtime.Object) *Fib {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(juneauv1alpha1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	return &Fib{client: cl, snapshots: make(map[string]fibSnapshot)}
}

func peerSubnet() *juneauv1alpha1.Subnet {
	return &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-subnet"},
		Status: juneauv1alpha1.SubnetStatus{
			VNI:        77,
			GatewayMAC: "02:00:00:00:00:07",
		},
	}
}

func TestBuildFibValVpcPeeringForwardsToPeerSubnet(t *testing.T) {
	r := newFibFixture(t, peerSubnet())

	route := &juneauv1alpha1.Route{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via: juneauv1alpha1.RouteVia{
			Type:       juneauv1alpha1.ViaVpcPeering,
			VpcPeering: "peering-a",
		},
	}

	val, skip, err := r.buildFibVal(context.Background(), route)
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("buildFibVal skipped a vpcPeering route")
	}
	if val.Type != fibRouteTypePeering {
		t.Errorf("type = %d, want %d", val.Type, fibRouteTypePeering)
	}
	if val.SubnetId != 77 {
		t.Errorf("subnet ID = %d, want 77", val.SubnetId)
	}
	wantMAC := [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x07}
	if val.Smac != wantMAC {
		t.Errorf("smac = %v, want %v", val.Smac, wantMAC)
	}
	if val.Dmac != [6]uint8{} {
		t.Errorf("dmac = %v, want zero", val.Dmac)
	}
}

func TestBuildFibValVpcPeeringOnlyDiffersFromConnectedByType(t *testing.T) {
	r := newFibFixture(t, peerSubnet())

	connected, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.Route{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
	})
	if err != nil {
		t.Fatalf("buildFibVal connected: %v", err)
	}
	peering, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.Route{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: "peering-a"},
	})
	if err != nil {
		t.Fatalf("buildFibVal vpcPeering: %v", err)
	}

	if connected.Type == peering.Type {
		t.Fatalf("both route types render as %d", connected.Type)
	}
	peering.Type = connected.Type
	if peering != connected {
		t.Errorf("vpcPeering value = %+v, want the connected value %+v", peering, connected)
	}
}

func TestBuildFibValVpcPeeringMissingSubnetFails(t *testing.T) {
	r := newFibFixture(t)

	_, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.Route{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: "peering-a"},
	})
	if err == nil {
		t.Fatal("buildFibVal accepted a vpcPeering route with no peer Subnet")
	}
}
