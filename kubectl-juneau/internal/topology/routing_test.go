package topology

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// stubView is a minimal fake View used for resolver unit tests. Each
// field is the canonical "X-by-name" lookup; missing entries return
// (nil, nil) per the View contract.
type stubView struct {
	vpcs        map[string]*juneauv1alpha1.Vpc
	subnets     map[string]*juneauv1alpha1.Subnet
	routeTables map[string]*juneauv1alpha1.RouteTable
}

func (s *stubView) Pod(_ context.Context, _, _ string) (*corev1.Pod, error)         { return nil, nil }
func (s *stubView) Service(_ context.Context, _, _ string) (*corev1.Service, error) { return nil, nil }
func (s *stubView) EndpointSlicesForService(_ context.Context, _, _ string) ([]discoveryv1.EndpointSlice, error) {
	return nil, nil
}
func (s *stubView) Vpc(_ context.Context, name string) (*juneauv1alpha1.Vpc, error) {
	return s.vpcs[name], nil
}
func (s *stubView) Subnet(_ context.Context, name string) (*juneauv1alpha1.Subnet, error) {
	return s.subnets[name], nil
}
func (s *stubView) RouteTable(_ context.Context, name string) (*juneauv1alpha1.RouteTable, error) {
	return s.routeTables[name], nil
}
func (s *stubView) NetworkInterface(_ context.Context, _, _ string) (*juneauv1alpha1.NetworkInterface, error) {
	return nil, nil
}
func (s *stubView) SecurityGroup(_ context.Context, _ string) (*juneauv1alpha1.SecurityGroup, error) {
	return nil, nil
}
func (s *stubView) NetworkACL(_ context.Context, _ string) (*juneauv1alpha1.NetworkACL, error) {
	return nil, nil
}
func (s *stubView) NATGateway(_ context.Context, _ string) (*juneauv1alpha1.NATGateway, error) {
	return nil, nil
}
func (s *stubView) SubnetsByVpc(_ context.Context, _ string) ([]juneauv1alpha1.Subnet, error) {
	return nil, nil
}
func (s *stubView) RouteTablesByVpc(_ context.Context, _ string) ([]juneauv1alpha1.RouteTable, error) {
	return nil, nil
}
func (s *stubView) SecurityGroupsByVpc(_ context.Context, _ string) ([]juneauv1alpha1.SecurityGroup, error) {
	return nil, nil
}
func (s *stubView) NetworkACLsByVpc(_ context.Context, _ string) ([]juneauv1alpha1.NetworkACL, error) {
	return nil, nil
}
func (s *stubView) NATGatewaysByVpc(_ context.Context, _ string) ([]juneauv1alpha1.NATGateway, error) {
	return nil, nil
}
func (s *stubView) NetworkInterfacesByPod(_ context.Context, _, _ string) ([]juneauv1alpha1.NetworkInterface, error) {
	return nil, nil
}
func (s *stubView) NetworkInterfacesBySubnet(_ context.Context, _ string) ([]juneauv1alpha1.NetworkInterface, error) {
	return nil, nil
}
func (s *stubView) ElasticIPAttachmentsForNIC(_ context.Context, _ string) ([]juneauv1alpha1.ElasticIPAttachment, error) {
	return nil, nil
}
func (s *stubView) ElasticIP(_ context.Context, _ string) (*juneauv1alpha1.ElasticIP, error) {
	return nil, nil
}

func TestResolveRouteTableForSubnet(t *testing.T) {
	mainRT := &juneauv1alpha1.RouteTable{}
	mainRT.Name = "app-vpc"
	overrideRT := &juneauv1alpha1.RouteTable{}
	overrideRT.Name = "subnet-rt"

	vpc := &juneauv1alpha1.Vpc{}
	vpc.Name = "app-vpc"
	vpc.Status.MainRouteTable = "app-vpc"

	view := &stubView{
		vpcs:        map[string]*juneauv1alpha1.Vpc{"app-vpc": vpc},
		routeTables: map[string]*juneauv1alpha1.RouteTable{"app-vpc": mainRT, "subnet-rt": overrideRT},
	}

	tests := []struct {
		name       string
		subnet     *juneauv1alpha1.Subnet
		vpc        *juneauv1alpha1.Vpc
		wantRT     string
		wantIsMain bool
	}{
		{
			name:       "nil subnet returns nil",
			subnet:     nil,
			vpc:        vpc,
			wantRT:     "",
			wantIsMain: false,
		},
		{
			name: "no override falls back to main",
			subnet: &juneauv1alpha1.Subnet{
				Spec: juneauv1alpha1.SubnetSpec{Vpc: "app-vpc"},
			},
			vpc:        vpc,
			wantRT:     "app-vpc",
			wantIsMain: true,
		},
		{
			name: "override wins over main",
			subnet: &juneauv1alpha1.Subnet{
				Spec: juneauv1alpha1.SubnetSpec{Vpc: "app-vpc", RouteTable: "subnet-rt"},
			},
			vpc:        vpc,
			wantRT:     "subnet-rt",
			wantIsMain: false,
		},
		{
			name: "override that does not exist returns nil but override flag",
			subnet: &juneauv1alpha1.Subnet{
				Spec: juneauv1alpha1.SubnetSpec{Vpc: "app-vpc", RouteTable: "missing"},
			},
			vpc:        vpc,
			wantRT:     "",
			wantIsMain: false,
		},
		{
			name: "vpc with no main route table returns nil with isMain=true",
			subnet: &juneauv1alpha1.Subnet{
				Spec: juneauv1alpha1.SubnetSpec{Vpc: "x"},
			},
			vpc:        &juneauv1alpha1.Vpc{},
			wantRT:     "",
			wantIsMain: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, isMain, err := resolveRouteTableForSubnet(context.Background(), view, tc.subnet, tc.vpc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotName := ""
			if got != nil {
				gotName = got.Name
			}
			if gotName != tc.wantRT {
				t.Fatalf("rt name: want %q, got %q", tc.wantRT, gotName)
			}
			if isMain != tc.wantIsMain {
				t.Fatalf("isMain: want %t, got %t", tc.wantIsMain, isMain)
			}
		})
	}
}

func TestSummariseRouteTablePrefersStatus(t *testing.T) {
	rt := &juneauv1alpha1.RouteTable{
		Spec: juneauv1alpha1.RouteTableSpec{
			Vpc: "v",
			Routes: []juneauv1alpha1.Route{{
				Dst: "10.0.0.0/24",
				Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
			}},
		},
		Status: juneauv1alpha1.RouteTableStatus{
			Routes: []juneauv1alpha1.Route{{
				Dst: "10.0.0.0/24", Subnet: "a",
				Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
			}, {
				Dst: "0.0.0.0/0",
				Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaNATGateway, NATGateway: "g"},
			}},
		},
	}
	rt.Name = "vpc-rt"

	got := summariseRouteTable(rt, true)
	if got == nil {
		t.Fatal("got nil summary")
	}
	if !got.IsMain {
		t.Fatal("expected isMain=true")
	}
	if len(got.Routes) != 2 {
		t.Fatalf("expected status routes (2), got %d", len(got.Routes))
	}
	if got.Routes[0].Subnet != "a" {
		t.Fatalf("expected first route subnet=a (status), got %q", got.Routes[0].Subnet)
	}
}

// stubViewError tests that resolver errors propagate.
type stubViewError struct{ stubView }

func (s *stubViewError) RouteTable(_ context.Context, _ string) (*juneauv1alpha1.RouteTable, error) {
	return nil, errBoom
}

var errBoom = errors.New("boom")

func TestResolveRouteTableForSubnetPropagatesError(t *testing.T) {
	v := &stubViewError{}
	subnet := &juneauv1alpha1.Subnet{Spec: juneauv1alpha1.SubnetSpec{Vpc: "v", RouteTable: "x"}}
	if _, _, err := resolveRouteTableForSubnet(context.Background(), v, subnet, &juneauv1alpha1.Vpc{}); !errors.Is(err, errBoom) {
		t.Fatalf("expected errBoom, got %v", err)
	}
}
