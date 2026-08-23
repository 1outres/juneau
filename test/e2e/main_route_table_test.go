package e2e

import "testing"

func TestMainRouteTablePatch(t *testing.T) {
	tests := []struct {
		name   string
		routes []route
		want   string
	}{
		{
			name:   "no route clears the list",
			routes: nil,
			want:   `{"spec":{"routes":[]}}`,
		},
		{
			name:   "internet gateway route",
			routes: []route{internetGatewayRoute("0.0.0.0/0")},
			want:   `{"spec":{"routes":[{"dst":"0.0.0.0/0","via":{"type":"internetGateway"}}]}}`,
		},
		{
			name:   "nat gateway route",
			routes: []route{natGatewayRoute("0.0.0.0/0", "e2e-nat-gw")},
			want:   `{"spec":{"routes":[{"dst":"0.0.0.0/0","via":{"type":"natGateway","natGateway":"e2e-nat-gw"}}]}}`,
		},
		{
			name:   "vpc peering route",
			routes: []route{vpcPeeringRoute("10.128.0.0/24", "peering-a-b")},
			want:   `{"spec":{"routes":[{"dst":"10.128.0.0/24","via":{"type":"vpcPeering","vpcPeering":"peering-a-b"}}]}}`,
		},
		{
			name: "transit gateway routes keep their order",
			routes: []route{
				transitGatewayRoute("10.128.0.0/24", "tgw"),
				transitGatewayRoute("10.129.0.0/24", "tgw"),
			},
			want: `{"spec":{"routes":[` +
				`{"dst":"10.128.0.0/24","via":{"type":"transitGateway","transitGateway":"tgw"}},` +
				`{"dst":"10.129.0.0/24","via":{"type":"transitGateway","transitGateway":"tgw"}}` +
				`]}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mainRouteTablePatch(tc.routes...)
			if err != nil {
				t.Fatalf("mainRouteTablePatch returned an error: %v", err)
			}
			if got != tc.want {
				t.Errorf("mainRouteTablePatch = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestVpcWithMainRouteTableManifest(t *testing.T) {
	tests := []struct {
		name   string
		vpc    string
		routes []route
		want   string
	}{
		{
			name:   "no route declares an empty route list",
			vpc:    "vpc-a",
			routes: nil,
			want: `apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: vpc-a
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: vpc-a
spec:
  vpc: vpc-a
  routes: []
`,
		},
		{
			name:   "the RouteTable carries the Vpc name",
			vpc:    "vpc-b",
			routes: []route{internetGatewayRoute("0.0.0.0/0")},
			want: `apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: vpc-b
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: vpc-b
spec:
  vpc: vpc-b
  routes: [{"dst":"0.0.0.0/0","via":{"type":"internetGateway"}}]
`,
		},
		{
			name: "every declared route keeps its order",
			vpc:  "vpc-c",
			routes: []route{
				internetGatewayRoute("0.0.0.0/0"),
				vpcPeeringRoute("10.128.0.0/24", "peering-a-b"),
			},
			want: `apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: vpc-c
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: vpc-c
spec:
  vpc: vpc-c
  routes: [{"dst":"0.0.0.0/0","via":{"type":"internetGateway"}},` +
				`{"dst":"10.128.0.0/24","via":{"type":"vpcPeering","vpcPeering":"peering-a-b"}}]
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vpcWithMainRouteTableManifest(tc.vpc, tc.routes...)
			if err != nil {
				t.Fatalf("vpcWithMainRouteTableManifest returned an error: %v", err)
			}
			if got != tc.want {
				t.Errorf("vpcWithMainRouteTableManifest =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}
