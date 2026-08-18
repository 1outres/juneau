package bootstrap

import (
	"context"
	"errors"
	"net"
	"testing"

	toolscache "k8s.io/client-go/tools/cache"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/runner"
)

func testIdentity(t *testing.T) *JuneauNodeIdentity {
	t.Helper()
	identity, err := parseJuneauNodeIdentity(identityEndpoint("10.16.0.9/16", "02:00:0a:10:00:09"))
	if err != nil {
		t.Fatalf("parseJuneauNodeIdentity: %v", err)
	}
	return identity
}

func mustParseMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return mac
}

func mustParseAddr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return &net.IPNet{IP: ip, Mask: ipnet.Mask}
}

func addrStrings(addrs []*net.IPNet) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func TestPlanJuneauNodeConvergenceLeavesAMatchingLinkAlone(t *testing.T) {
	identity := testIdentity(t)
	plan := planJuneauNodeConvergence(juneauNodeLinkState{
		MAC:       mustParseMAC(t, "02:00:0a:10:00:09"),
		Addresses: []*net.IPNet{mustParseAddr(t, "10.16.0.9/16")},
	}, identity)

	if plan.SetMAC || plan.AddAddress || len(plan.DeleteAddrs) != 0 {
		t.Errorf("plan = %+v, want no changes", plan)
	}
}

func TestPlanJuneauNodeConvergenceRewritesTheKernelMAC(t *testing.T) {
	// The random MAC an older daemon left behind, which is exactly what
	// the upgrade to a controller-owned identity has to overwrite.
	identity := testIdentity(t)
	plan := planJuneauNodeConvergence(juneauNodeLinkState{
		MAC:       mustParseMAC(t, "06:d5:49:80:ba:c1"),
		Addresses: []*net.IPNet{mustParseAddr(t, "10.16.0.9/16")},
	}, identity)

	if !plan.SetMAC {
		t.Error("SetMAC = false, want true")
	}
	if plan.AddAddress || len(plan.DeleteAddrs) != 0 {
		t.Errorf("plan = %+v, want the address left alone", plan)
	}
}

func TestPlanJuneauNodeConvergenceAddsAMissingAddress(t *testing.T) {
	identity := testIdentity(t)
	plan := planJuneauNodeConvergence(juneauNodeLinkState{
		MAC: mustParseMAC(t, "02:00:0a:10:00:09"),
	}, identity)

	if !plan.AddAddress {
		t.Error("AddAddress = false, want true")
	}
	if len(plan.DeleteAddrs) != 0 {
		t.Errorf("DeleteAddrs = %v, want none", addrStrings(plan.DeleteAddrs))
	}
}

func TestPlanJuneauNodeConvergenceReplacesAStaleAddress(t *testing.T) {
	identity := testIdentity(t)
	plan := planJuneauNodeConvergence(juneauNodeLinkState{
		MAC:       mustParseMAC(t, "02:00:0a:10:00:09"),
		Addresses: []*net.IPNet{mustParseAddr(t, "10.16.0.4/16")},
	}, identity)

	if !plan.AddAddress {
		t.Error("AddAddress = false, want true")
	}
	if got := addrStrings(plan.DeleteAddrs); len(got) != 1 || got[0] != "10.16.0.4/16" {
		t.Errorf("DeleteAddrs = %v, want [10.16.0.4/16]", got)
	}
}

func TestPlanJuneauNodeConvergenceDropsAStaleAddressListedAfterTheWantedOne(t *testing.T) {
	identity := testIdentity(t)
	plan := planJuneauNodeConvergence(juneauNodeLinkState{
		MAC: mustParseMAC(t, "02:00:0a:10:00:09"),
		Addresses: []*net.IPNet{
			mustParseAddr(t, "10.16.0.9/16"),
			mustParseAddr(t, "10.16.0.4/16"),
		},
	}, identity)

	if plan.AddAddress {
		t.Error("AddAddress = true, want false")
	}
	if got := addrStrings(plan.DeleteAddrs); len(got) != 1 || got[0] != "10.16.0.4/16" {
		t.Errorf("DeleteAddrs = %v, want [10.16.0.4/16]", got)
	}
}

func TestPlanJuneauNodeConvergenceKeepsIPv6LinkLocal(t *testing.T) {
	identity := testIdentity(t)
	plan := planJuneauNodeConvergence(juneauNodeLinkState{
		MAC: mustParseMAC(t, "02:00:0a:10:00:09"),
		Addresses: []*net.IPNet{
			mustParseAddr(t, "10.16.0.9/16"),
			mustParseAddr(t, "fe80::400:aff:fe10:9/64"),
		},
	}, identity)

	if len(plan.DeleteAddrs) != 0 {
		t.Errorf("DeleteAddrs = %v, want none", addrStrings(plan.DeleteAddrs))
	}
}

func TestJuneauNodeConvergerEnqueueKey(t *testing.T) {
	converger := NewJuneauNodeConverger(nil, testNodeName)

	podEndpoint := testEndpoint(nil)
	podEndpoint.Spec.Kind = juneauv1alpha1.EndpointKindPod

	cases := []struct {
		name string
		obj  any
		want bool
	}{
		{name: "own node endpoint", obj: testEndpoint(nil), want: true},
		{name: "tombstone of own node endpoint", obj: toolscache.DeletedFinalStateUnknown{Obj: testEndpoint(nil)}, want: true},
		{name: "another node", obj: otherNodeEndpoint(), want: false},
		{name: "pod endpoint", obj: podEndpoint, want: false},
		{name: "unrelated object", obj: "not-an-endpoint", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := converger.EnqueueKey(tc.obj)
			if ok != tc.want {
				t.Fatalf("ok = %v, want %v", ok, tc.want)
			}
			if ok && key != runner.SingletonKey {
				t.Errorf("key = %q, want %q", key, runner.SingletonKey)
			}
		})
	}
}

func TestJuneauNodeConvergerNeedsAnEndpoint(t *testing.T) {
	// The startup path: no identity to realize, so the daemon has to
	// exit and let the DaemonSet restart be the retry. Reached before
	// any netlink call, so it is safe in a unit test.
	cl, _ := newPatchFixture()
	converger := NewJuneauNodeConverger(cl, testNodeName)

	_, err := converger.Converge(context.Background())
	if !errors.Is(err, ErrJuneauNodeEndpointNotFound) {
		t.Fatalf("err = %v, want ErrJuneauNodeEndpointNotFound", err)
	}
}

func TestJuneauNodeConvergerReconcileWaitsForTheEndpoint(t *testing.T) {
	// The work-queue path: the controller is between deleting and
	// recreating the object, and the create event is already coming.
	cl, _ := newPatchFixture()
	converger := NewJuneauNodeConverger(cl, testNodeName)

	for attempt := range 2 {
		if err := converger.Reconcile(context.Background(), runner.SingletonKey); err != nil {
			t.Fatalf("Reconcile attempt %d: %v", attempt, err)
		}
	}
}

func TestJuneauNodeConvergerReconcileReportsOtherErrors(t *testing.T) {
	// Two kind=Node endpoints for one node is a real fault, not a gap,
	// so it has to keep reaching the runner.
	legacy := testEndpoint(nil)
	legacy.Namespace = "juneau-system"
	cl, _ := newPatchFixture(testEndpoint(nil), legacy)
	converger := NewJuneauNodeConverger(cl, testNodeName)

	err := converger.Reconcile(context.Background(), runner.SingletonKey)
	if err == nil {
		t.Fatal("Reconcile accepted two endpoints for one node, want an error")
	}
	if errors.Is(err, ErrJuneauNodeEndpointNotFound) {
		t.Errorf("err = %v, want something other than ErrJuneauNodeEndpointNotFound", err)
	}
}

func TestJuneauNodeConvergerRejectsAnUnusableIdentity(t *testing.T) {
	cl, _ := newPatchFixture(identityEndpoint("10.16.0.9/16", ""))
	converger := NewJuneauNodeConverger(cl, testNodeName)

	if _, err := converger.Converge(context.Background()); err == nil {
		t.Fatal("Converge succeeded without a MAC, want an error")
	}
}
