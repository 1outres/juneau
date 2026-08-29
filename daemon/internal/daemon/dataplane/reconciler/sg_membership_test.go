package reconciler

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func newMembershipFixture(t *testing.T, objs ...runtime.Object) *SGMembership {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	return NewSGMembership(cl, nil)
}

func newMembershipVpc(name string, id uint32) *juneauv1alpha1.Vpc {
	return &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     juneauv1alpha1.VpcStatus{VpcID: id},
	}
}

func newMembershipInterface(subnet, l2Network string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-a-eth1"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			Subnet:    subnet,
			L2Network: l2Network,
		},
		Status: juneauv1alpha1.NetworkInterfaceStatus{Address: "10.60.0.5/24"},
	}
}

func newMembershipL2Network(name string, gateway bool) *juneauv1alpha1.L2Network {
	network := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "vpc-a", CIDR: "10.60.0.0/24"},
	}
	if gateway {
		network.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
	}
	return network
}

// A NIC on an L2Network carries its SecurityGroups the same way a NIC
// on a Subnet does. They are only ever consulted where the segment
// meets a program that reads policy, which is the gateway.
func TestSGMembershipResolvesTheVpcOfAnL2Network(t *testing.T) {
	r := newMembershipFixture(t, newMembershipL2Network("lab-net", true), newMembershipVpc("vpc-a", 11))

	vpc, ok, err := r.networkVpc(context.Background(), newMembershipInterface("", "lab-net"))
	if err != nil {
		t.Fatalf("networkVpc: %v", err)
	}
	if !ok {
		t.Fatal("the Vpc of the segment did not resolve")
	}
	if vpc.Status.VpcID != 11 {
		t.Errorf("resolved vpc id %d, want 11", vpc.Status.VpcID)
	}
}

// A segment with no gateway never meets a program that reads policy, so
// a rule written for a NIC on one could never fire. Writing the
// membership anyway would put entries in the map that nothing reads.
func TestSGMembershipSkipsASegmentWithNoGateway(t *testing.T) {
	r := newMembershipFixture(t, newMembershipL2Network("lab-net", false), newMembershipVpc("vpc-a", 11))

	if _, ok, err := r.networkVpc(context.Background(), newMembershipInterface("", "lab-net")); err != nil || ok {
		t.Errorf("networkVpc = ok %v, err %v; want the NIC left out", ok, err)
	}
}

func TestSGMembershipResolvesTheVpcOfASubnet(t *testing.T) {
	subnet := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
		Spec:       juneauv1alpha1.SubnetSpec{Vpc: "vpc-a", CIDR: "10.61.0.0/24"},
	}
	r := newMembershipFixture(t, subnet, newMembershipVpc("vpc-a", 11))

	vpc, ok, err := r.networkVpc(context.Background(), newMembershipInterface("web", ""))
	if err != nil {
		t.Fatalf("networkVpc: %v", err)
	}
	if !ok {
		t.Fatal("the Vpc of the Subnet did not resolve")
	}
	if vpc.Status.VpcID != 11 {
		t.Errorf("resolved vpc id %d, want 11", vpc.Status.VpcID)
	}
}

// The id lands after the Vpc exists. A membership written under 0 would
// name a Vpc the data plane never stamps a packet with.
func TestSGMembershipWaitsForTheVpcID(t *testing.T) {
	r := newMembershipFixture(t, newMembershipL2Network("lab-net", true), newMembershipVpc("vpc-a", 0))

	if _, ok, err := r.networkVpc(context.Background(), newMembershipInterface("", "lab-net")); err != nil || ok {
		t.Errorf("networkVpc = ok %v, err %v; want the NIC left out", ok, err)
	}
}

func TestSGMembershipLeavesANicThatNamesNoNetwork(t *testing.T) {
	r := newMembershipFixture(t, newMembershipVpc("vpc-a", 11))

	if _, ok, err := r.networkVpc(context.Background(), newMembershipInterface("", "")); err != nil || ok {
		t.Errorf("networkVpc = ok %v, err %v; want the NIC left out", ok, err)
	}
}
