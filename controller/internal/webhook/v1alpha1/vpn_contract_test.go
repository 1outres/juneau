package v1alpha1

import (
	"context"
	"net"
	"strings"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNContract(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "subnet"}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.20.0.0/24"}}
	external := &juneau.ExternalNetwork{ObjectMeta: metav1.ObjectMeta{Name: "wan"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "psk", Namespace: "site"}, Data: map[string][]byte{"key": []byte("secret")}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, subnet, external, secret).Build()
	validator := &VPNCustomValidator{Reader: reader}
	base := func() *juneau.VPN {
		return &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site-a", Namespace: "site"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "subnet", ExternalNetwork: "wan", LocalASN: 65001, RemoteASN: 65002, PeerIKEID: "branch.example", PSKSecretRef: juneau.VPNSecretRef{Name: "psk", Key: "key"}}}
	}
	cases := []struct {
		name   string
		modify func(*juneau.VPN)
		want   string
	}{
		{"valid", func(*juneau.VPN) {}, ""},
		{"max asn", func(x *juneau.VPN) { x.Spec.RemoteASN = 4294967295 }, ""},
		{"too large asn", func(x *juneau.VPN) { x.Spec.RemoteASN = 4294967296 }, "spec.remoteASN"},
		{"wrong namespace secret", func(x *juneau.VPN) { x.Namespace = "elsewhere" }, "spec.pskSecretRef.name"},
		{"missing vpc", func(x *juneau.VPN) { x.Spec.Vpc = "missing" }, "spec.vpc"},
		{"bad vpc name", func(x *juneau.VPN) { x.Spec.Vpc = "Not-A-Vpc" }, "spec.vpc"},
		{"subnet wrong vpc", func(x *juneau.VPN) { x.Spec.Vpc = "other" }, "spec.subnet"},
		{"missing subnet", func(x *juneau.VPN) { x.Spec.Subnet = "missing" }, "spec.subnet"},
		{"missing network", func(x *juneau.VPN) { x.Spec.ExternalNetwork = "missing" }, "spec.externalNetwork"},
		{"missing secret", func(x *juneau.VPN) { x.Spec.PSKSecretRef.Name = "missing" }, "spec.pskSecretRef"},
		{"missing secret key", func(x *juneau.VPN) { x.Spec.PSKSecretRef.Key = "missing" }, "spec.pskSecretRef.key"},
		{"same asn", func(x *juneau.VPN) { x.Spec.RemoteASN = x.Spec.LocalASN }, "spec.remoteASN"},
		{"zero asn", func(x *juneau.VPN) { x.Spec.LocalASN = 0 }, "spec.localASN"},
		{"bad public IP", func(x *juneau.VPN) { x.Spec.RequestedPublicIP = "2001:db8::1" }, "spec.requestedPublicIP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := base()
			tc.modify(x)
			_, err := validator.ValidateCreate(ctx, x)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s: %v", tc.want, err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*juneau.VPN)
		want   string
	}{
		{"subnet", func(x *juneau.VPN) { x.Spec.Subnet = "other" }, "spec.subnet"},
		{"external network", func(x *juneau.VPN) { x.Spec.ExternalNetwork = "other" }, "spec.externalNetwork"},
		{"requested public IP", func(x *juneau.VPN) { x.Spec.RequestedPublicIP = "198.51.100.5" }, "spec.requestedPublicIP"},
	} {
		t.Run("immutable "+tc.name, func(t *testing.T) {
			old := base()
			changed := base()
			tc.change(changed)
			_, err := validator.ValidateUpdate(ctx, old, changed)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("immutable field %s: %v", tc.want, err)
			}
		})
	}
}

func TestVPNRouteValidation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = juneau.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "site"}, Spec: juneau.VPNSpec{Vpc: "vpc"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "subnet"}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.20.0.0/24"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Spec: juneau.VpcSpec{Service: &juneau.VpcServiceSpec{Consume: true}}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, subnet, vpc).Build()
	_, serviceCIDR, _ := net.ParseCIDR("10.96.0.0/12")
	validator := &RouteTableCustomValidator{Reader: reader, ServiceCIDR: serviceCIDR}
	base := func(dst string) *juneau.RouteTable {
		return &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "routes"}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: dst, Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}}}}}
	}
	cases := []struct {
		name, dst string
		modify    func(*juneau.RouteTable)
		want      string
	}{
		{"valid", "192.168.0.0/24", func(*juneau.RouteTable) {}, ""},
		{"default explicit", "0.0.0.0/0", func(*juneau.RouteTable) {}, ""},
		{"no name", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Routes[0].Via.VPN.Name = "" }, "via.vpn.name"},
		{"no namespace", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Routes[0].Via.VPN.Namespace = "" }, "via.vpn.namespace"},
		{"nil ref", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Routes[0].Via.VPN = nil }, "via.vpn"},
		{"bad namespace", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Routes[0].Via.VPN.Namespace = "NOT-A-NS" }, "via.vpn.namespace"},
		{"other namespace", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Routes[0].Via.VPN.Namespace = "other" }, "via.vpn"},
		{"wrong vpc", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Vpc = "other" }, "via.vpn"},
		{"missing vpn", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Routes[0].Via.VPN.Name = "unknown" }, "via.vpn"},
		{"overlapping subnet", "10.20.0.0/16", func(*juneau.RouteTable) {}, "routes[0].dst"},
		{"overlapping service", "10.100.0.0/16", func(*juneau.RouteTable) {}, "routes[0].dst"},
		{"noncanonical", "192.168.0.1/24", func(*juneau.RouteTable) {}, "routes[0].dst"},
		{"bad cidr", "not-a-cidr", func(*juneau.RouteTable) {}, "routes[0].dst"},
		{"ipv6", "2001:db8::/64", func(*juneau.RouteTable) {}, "routes[0].dst"},
		{"extra reference", "192.168.0.0/24", func(x *juneau.RouteTable) { x.Spec.Routes[0].Via.NATGateway = "nat" }, "via.natGateway"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := base(tc.dst)
			tc.modify(x)
			_, err := validator.ValidateCreate(ctx, x)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s: %v", tc.want, err)
			}
		})
	}
	if err := reader.Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "public-svc", Namespace: "default", Annotations: map[string]string{ServiceAnnotationVpc: "vpc"}}, Spec: corev1.ServiceSpec{ExternalIPs: []string{"198.51.100.10"}}}); err != nil {
		t.Fatal(err)
	}
	_, extErr := validator.ValidateCreate(ctx, base("198.51.100.0/24"))
	if extErr == nil || !strings.Contains(extErr.Error(), "Service") {
		t.Fatalf("reachable service external IP overlap: %v", extErr)
	}
	x := base("192.168.0.0/24")
	x.Spec.Routes = append(x.Spec.Routes, juneau.Route{Dst: "192.168.0.1/24", Via: x.Spec.Routes[0].Via})
	_, err := validator.ValidateCreate(ctx, x)
	if err == nil || !strings.Contains(err.Error(), "routes[1].dst") {
		t.Fatalf("canonical duplicate: %v", err)
	}
	if err := reader.Create(ctx, base("192.168.0.0/24")); err != nil {
		t.Fatal(err)
	}
	another := base("192.168.0.0/24")
	another.Name = "other-routes"
	if _, err := validator.ValidateCreate(ctx, another); err != nil {
		t.Fatalf("same CIDR in another RouteTable: %v", err)
	}
	_, err = (&VPNCustomValidator{Reader: reader}).ValidateDelete(ctx, vpn)
	if err == nil || !strings.Contains(err.Error(), "routes") {
		t.Fatalf("delete guard: %v", err)
	}
	other := vpn.DeepCopy()
	other.Namespace = "other"
	_, err = (&VPNCustomValidator{Reader: reader}).ValidateDelete(ctx, other)
	if err != nil {
		t.Fatalf("unrelated namespace must not block deletion: %v", err)
	}
}
