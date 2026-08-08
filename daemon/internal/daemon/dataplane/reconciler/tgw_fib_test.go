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

func newTgwFibFixture(t *testing.T, objects ...runtime.Object) *TgwFib {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(juneauv1alpha1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	return &TgwFib{client: cl, snapshots: make(map[string]fibSnapshot)}
}

func spokeSubnet() *juneauv1alpha1.Subnet {
	return &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "spoke-subnet"},
		Status: juneauv1alpha1.SubnetStatus{
			VNI:        91,
			GatewayMAC: "02:00:00:00:00:5b",
		},
	}
}

func TestTgwBuildFibValForwardsToTargetSubnet(t *testing.T) {
	r := newTgwFibFixture(t, spokeSubnet())

	val, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedTransitGatewayRoute{
		Dst:        "10.2.0.0/24",
		Attachment: "spoke",
		Subnet:     "spoke-subnet",
		Origin:     juneauv1alpha1.TransitGatewayRouteOriginPropagated,
	})
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if val.Type != fibRouteTypeConnected {
		t.Errorf("type = %d, want %d", val.Type, fibRouteTypeConnected)
	}
	if val.SubnetId != 91 {
		t.Errorf("subnet ID = %d, want 91", val.SubnetId)
	}
	wantMAC := [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x5b}
	if val.Smac != wantMAC {
		t.Errorf("smac = %v, want %v", val.Smac, wantMAC)
	}
	if val.Dmac != [6]uint8{} {
		t.Errorf("dmac = %v, want zero", val.Dmac)
	}
}

func TestTgwBuildFibValBlackholeNeedsNoSubnet(t *testing.T) {
	r := newTgwFibFixture(t)

	val, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedTransitGatewayRoute{
		Dst:       "10.9.0.0/24",
		Blackhole: true,
		Origin:    juneauv1alpha1.TransitGatewayRouteOriginStatic,
	})
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if val.Type != fibRouteTypeBlackhole {
		t.Errorf("type = %d, want %d", val.Type, fibRouteTypeBlackhole)
	}
	if val.SubnetId != 0 {
		t.Errorf("subnet ID = %d, want 0", val.SubnetId)
	}
	if val.Smac != [6]uint8{} {
		t.Errorf("smac = %v, want zero", val.Smac)
	}
}

func TestTgwBuildFibValMissingSubnetFails(t *testing.T) {
	r := newTgwFibFixture(t)

	_, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedTransitGatewayRoute{
		Dst:    "10.2.0.0/24",
		Subnet: "spoke-subnet",
		Origin: juneauv1alpha1.TransitGatewayRouteOriginPropagated,
	})
	if err == nil {
		t.Fatal("buildFibVal accepted a route whose target Subnet does not exist")
	}
}

func TestTgwFanOutListsEveryRouteTable(t *testing.T) {
	r := newTgwFibFixture(t,
		&juneauv1alpha1.TransitGatewayRouteTable{ObjectMeta: metav1.ObjectMeta{Name: "hub"}},
		&juneauv1alpha1.TransitGatewayRouteTable{ObjectMeta: metav1.ObjectMeta{Name: "spoke"}},
	)

	keys := r.FanOutAllTransitGatewayRouteTables(nil)
	if len(keys) != 2 {
		t.Fatalf("fan-out returned %v, want both route tables", keys)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	if !seen["hub"] || !seen["spoke"] {
		t.Errorf("fan-out returned %v, want hub and spoke", keys)
	}
}
