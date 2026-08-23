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
