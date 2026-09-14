package grpc

import (
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func nicWithAddress(ifname string, spec juneauv1alpha1.NetworkInterfaceSpec, address string) *juneauv1alpha1.NetworkInterface {
	spec.PodRef = juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-web", Name: "web", Interface: ifname}
	return &juneauv1alpha1.NetworkInterface{
		Spec:   spec,
		Status: juneauv1alpha1.NetworkInterfaceStatus{Address: address},
	}
}

func TestHostRouteToPodCoversOnlyAnElasticIPOnEth0(t *testing.T) {
	for _, tc := range []struct {
		name    string
		nwiface *juneauv1alpha1.NetworkInterface
		want    string
	}{
		{
			name:    "elasticIP on eth0",
			nwiface: nicWithAddress("eth0", juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"}, "203.0.113.10/32"),
			want:    "203.0.113.10/32",
		},
		{
			name:    "elasticIP on an extra NIC",
			nwiface: nicWithAddress("eth1", juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"}, "203.0.113.10/32"),
		},
		{
			name:    "subnet on eth0",
			nwiface: nicWithAddress("eth0", juneauv1alpha1.NetworkInterfaceSpec{Subnet: "default"}, "10.16.0.5/16"),
		},
		{
			name:    "l2Network on eth0",
			nwiface: nicWithAddress("eth0", juneauv1alpha1.NetworkInterfaceSpec{L2Network: "segment"}, "192.168.10.5/24"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hostRouteToPod(tc.nwiface)
			if err != nil {
				t.Fatalf("hostRouteToPod: %v", err)
			}
			switch {
			case tc.want == "" && got != nil:
				t.Errorf("host route = %s, want none", got)
			case tc.want != "" && (got == nil || got.String() != tc.want):
				t.Errorf("host route = %v, want %s", got, tc.want)
			}
		})
	}
}

func TestHostRouteToPodRejectsAnElasticIPThatIsNotASingleIPv4Address(t *testing.T) {
	for _, address := range []string{"", "203.0.113.10/24", "2001:db8::10/128", "203.0.113.10"} {
		nwiface := nicWithAddress("eth0", juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"}, address)
		if got, err := hostRouteToPod(nwiface); err == nil {
			t.Errorf("address %q: host route = %v, want an error", address, got)
		}
	}
}

func hostRoutesVia(t *testing.T, link netlink.Link) []netlink.Route {
	t.Helper()
	return routesOf(t, link, unix.RT_TABLE_MAIN)
}

func TestInstallHostRouteToPodIsIdempotent(t *testing.T) {
	enterTestNetns(t)
	veth := addTestLink(t, "eth0+012345")
	dst := mustHostRoute(t, "203.0.113.10/32")

	for range 2 {
		if err := installHostRouteToPod(dst, veth.Attrs().Index); err != nil {
			t.Fatalf("installHostRouteToPod: %v", err)
		}
	}
	routes := hostRoutesVia(t, veth)
	if len(routes) != 1 || routes[0].Dst.String() != "203.0.113.10/32" || routes[0].Scope != netlink.SCOPE_LINK {
		t.Errorf("routes via the veth = %v, want one scope link route to 203.0.113.10/32", routes)
	}
	if err := verifyHostRouteToPod(dst, veth.Attrs().Name); err != nil {
		t.Errorf("verifyHostRouteToPod: %v", err)
	}
}

// A new sandbox of the same Pod can come up before the DEL of the old one
// has run. The route has to follow the new veth, and the late DEL must not
// take it away.
func TestHostRouteToPodMovesToTheNewSandboxAndSurvivesTheOldDel(t *testing.T) {
	enterTestNetns(t)
	oldVeth := addTestLink(t, "eth0+aaaaaa")
	newVeth := addTestLink(t, "eth0+bbbbbb")
	dst := mustHostRoute(t, "203.0.113.10/32")

	if err := installHostRouteToPod(dst, oldVeth.Attrs().Index); err != nil {
		t.Fatalf("install via the old veth: %v", err)
	}
	if err := installHostRouteToPod(dst, newVeth.Attrs().Index); err != nil {
		t.Fatalf("install via the new veth: %v", err)
	}
	if err := verifyHostRouteToPod(dst, oldVeth.Attrs().Name); err == nil {
		t.Error("the route still leaves through the old veth")
	}

	if err := removeHostRoutesVia(oldVeth); err != nil {
		t.Fatalf("removeHostRoutesVia the old veth: %v", err)
	}
	if err := verifyHostRouteToPod(dst, newVeth.Attrs().Name); err != nil {
		t.Errorf("the DEL of the old sandbox took the route of the new one: %v", err)
	}

	if err := removeHostRoutesVia(newVeth); err != nil {
		t.Fatalf("removeHostRoutesVia the new veth: %v", err)
	}
	if routes := hostRoutesVia(t, newVeth); len(routes) != 0 {
		t.Errorf("routes via the new veth after its DEL = %v, want none", routes)
	}
	if err := verifyHostRouteToPod(dst, newVeth.Attrs().Name); err == nil {
		t.Error("verifyHostRouteToPod found a route that was removed")
	}
}

func TestRemoveHostRouteToPod(t *testing.T) {
	enterTestNetns(t)
	veth := addTestLink(t, "eth0+012345")
	dst := mustHostRoute(t, "203.0.113.10/32")
	if err := installHostRouteToPod(dst, veth.Attrs().Index); err != nil {
		t.Fatalf("installHostRouteToPod: %v", err)
	}

	if err := removeHostRouteToPod(dst, veth.Attrs().Index); err != nil {
		t.Fatalf("removeHostRouteToPod: %v", err)
	}
	if routes := hostRoutesVia(t, veth); len(routes) != 0 {
		t.Errorf("routes via the veth = %v, want none", routes)
	}
	if err := removeHostRouteToPod(dst, veth.Attrs().Index); err != nil {
		t.Errorf("removing a route that is gone: %v", err)
	}
}

func mustHostRoute(t *testing.T, address string) *hostRoute {
	t.Helper()
	nwiface := nicWithAddress("eth0", juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"}, address)
	dst, err := hostRouteToPod(nwiface)
	if err != nil || dst == nil {
		t.Fatalf("hostRouteToPod(%s) = %v, %v", address, dst, err)
	}
	return dst
}
