package prefixsource

import (
	"context"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newBGPExternalNetwork(name string) *juneauv1alpha1.ExternalNetwork {
	return &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
			AddressPools: []string{"some-pool"},
		},
	}
}

func newARPExternalNetwork(name string) *juneauv1alpha1.ExternalNetwork {
	return &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         juneauv1alpha1.ExternalNetworkTypeARP,
			AddressPools: []string{"some-pool"},
		},
	}
}

func newReadySLB(name, namespace, vip, externalNet string, advertisingNodes ...string) *juneauv1alpha1.ServiceLoadBalancer {
	return &juneauv1alpha1.ServiceLoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: juneauv1alpha1.ServiceLoadBalancerSpec{
			ServiceRef:      juneauv1alpha1.ServiceLoadBalancerServiceReference{Name: name},
			ExternalNetwork: externalNet,
		},
		Status: juneauv1alpha1.ServiceLoadBalancerStatus{
			VIP:              vip,
			AdvertisingNodes: append([]string(nil), advertisingNodes...),
		},
	}
}

func TestServiceLoadBalancerSource_AdvertisesVIPOnEligibleNode(t *testing.T) {
	t.Parallel()

	en := newBGPExternalNetwork("public")
	slb := newReadySLB("web", "app", "203.0.113.10", "public", "node-a", "node-c")

	cl := newFakeClient(t, en, slb)
	res, err := ServiceLoadBalancerSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(res.Advertisements); got != 1 {
		t.Fatalf("Advertisements: want 1, got %d", got)
	}
	ad := res.Advertisements[0]
	if ad.SourceKind != "ServiceLoadBalancer" || ad.SourceNamespace != "app" || ad.SourceName != "web" {
		t.Errorf("attribution: got %+v", ad)
	}
	if got := ad.Prefixes[0].String(); got != "203.0.113.10/32" {
		t.Errorf("prefix: want 203.0.113.10/32, got %s", got)
	}
}

func TestServiceLoadBalancerSource_SkipsNonAdvertisingNode(t *testing.T) {
	t.Parallel()

	en := newBGPExternalNetwork("public")
	slb := newReadySLB("web", "app", "203.0.113.10", "public", "node-c")

	cl := newFakeClient(t, en, slb)
	res, err := ServiceLoadBalancerSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Advertisements) != 0 {
		t.Errorf("expected no advertisements on non-listed node, got %v", res.Advertisements)
	}
}

func TestServiceLoadBalancerSource_SkipsWhenVIPIsEmpty(t *testing.T) {
	t.Parallel()

	en := newBGPExternalNetwork("public")
	slb := newReadySLB("web", "app", "", "public", "node-a")

	cl := newFakeClient(t, en, slb)
	res, err := ServiceLoadBalancerSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Advertisements) != 0 {
		t.Errorf("expected no advertisements when VIP is empty, got %v", res.Advertisements)
	}
}

func TestServiceLoadBalancerSource_SkipsARPExternalNetworkWithSoftError(t *testing.T) {
	t.Parallel()

	en := newARPExternalNetwork("public-arp")
	slb := newReadySLB("web", "app", "203.0.113.10", "public-arp", "node-a")

	cl := newFakeClient(t, en, slb)
	res, err := ServiceLoadBalancerSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Advertisements) != 0 {
		t.Errorf("expected no advertisements for arp ExternalNetwork, got %v", res.Advertisements)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected 1 soft error, got %v", res.Errors)
	}
	if res.Errors[0].ResourceKind != "ServiceLoadBalancer" {
		t.Errorf("Errors[0].ResourceKind: %s", res.Errors[0].ResourceKind)
	}
	const wantMessage = `ExternalNetwork "public-arp" is ARP-mode; the VIP is announced via ARPAdvertisement`
	if res.Errors[0].Message != wantMessage {
		t.Errorf("Errors[0].Message = %q, want %q", res.Errors[0].Message, wantMessage)
	}
}

func TestServiceLoadBalancerSource_RecordsErrorOnMissingExternalNetwork(t *testing.T) {
	t.Parallel()

	slb := newReadySLB("web", "app", "203.0.113.10", "missing", "node-a")
	cl := newFakeClient(t, slb)
	res, err := ServiceLoadBalancerSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Advertisements) != 0 {
		t.Errorf("expected no advertisements, got %v", res.Advertisements)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected 1 error, got %v", res.Errors)
	}
}

func TestServiceLoadBalancerSource_RecordsErrorOnInvalidVIP(t *testing.T) {
	t.Parallel()

	en := newBGPExternalNetwork("public")
	slb := newReadySLB("web", "app", "not-an-ip", "public", "node-a")
	cl := newFakeClient(t, en, slb)
	res, err := ServiceLoadBalancerSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Advertisements) != 0 {
		t.Errorf("expected no advertisements, got %v", res.Advertisements)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected 1 error, got %v", res.Errors)
	}
}

func TestServiceLoadBalancerSource_MultipleSLBsSortDeterministically(t *testing.T) {
	t.Parallel()

	en := newBGPExternalNetwork("public")
	slbs := []client.Object{
		en,
		newReadySLB("zeta", "ns2", "203.0.113.30", "public", "node-a"),
		newReadySLB("alpha", "ns1", "203.0.113.10", "public", "node-a"),
		newReadySLB("alpha", "ns2", "203.0.113.20", "public", "node-a"),
	}
	cl := newFakeClient(t, slbs...)
	res, err := ServiceLoadBalancerSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(res.Advertisements); got != 3 {
		t.Fatalf("Advertisements: want 3, got %d", got)
	}
	want := []struct {
		ns, n string
	}{
		{"ns1", "alpha"},
		{"ns2", "alpha"},
		{"ns2", "zeta"},
	}
	for i, w := range want {
		if res.Advertisements[i].SourceNamespace != w.ns || res.Advertisements[i].SourceName != w.n {
			t.Errorf("Advertisements[%d]: want %s/%s, got %s/%s", i, w.ns, w.n, res.Advertisements[i].SourceNamespace, res.Advertisements[i].SourceName)
		}
	}
}
