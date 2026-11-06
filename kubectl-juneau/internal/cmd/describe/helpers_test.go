package describe

import (
	"testing"

	"github.com/1outres/juneau/kubectl-juneau/internal/topology"
)

func TestFormatRouteVia(t *testing.T) {
	tests := []struct {
		name  string
		route topology.RouteSummary
		want  string
	}{
		{
			name:  "empty type",
			route: topology.RouteSummary{},
			want:  "-",
		},
		{
			name:  "connected with subnet",
			route: topology.RouteSummary{Type: "connected", Subnet: "subnet-a"},
			want:  "connected (subnet-a)",
		},
		{
			name:  "connected without subnet",
			route: topology.RouteSummary{Type: "connected"},
			want:  "connected",
		},
		{
			name:  "endpoint resolved to a NetworkEndpoint",
			route: topology.RouteSummary{Type: "endpoint", Endpoint: "net/router/eth0", NetworkEndpoint: "net/router-a.eth0", State: "Active"},
			want:  "endpoint (net/router/eth0 -> net/router-a.eth0)",
		},
		{
			name:  "endpoint that is blackholed",
			route: topology.RouteSummary{Type: "endpoint", Endpoint: "net/router/eth0", State: "Blackhole", Message: "no Pod"},
			want:  "endpoint (net/router/eth0) blackhole: no Pod",
		},
		{
			name:  "blackhole",
			route: topology.RouteSummary{Type: "blackhole", State: "Blackhole"},
			want:  "blackhole",
		},
		{
			name:  "internetGateway",
			route: topology.RouteSummary{Type: "internetGateway"},
			want:  "internetGateway",
		},
		{
			name:  "natGateway",
			route: topology.RouteSummary{Type: "natGateway", NATGateway: "egress"},
			want:  "natGateway (egress)",
		},
		{
			name:  "natGateway without name",
			route: topology.RouteSummary{Type: "natGateway"},
			want:  "natGateway (-)",
		},
		{
			name:  "vpcPeering with resolved subnet",
			route: topology.RouteSummary{Type: "vpcPeering", VpcPeering: "link", Subnet: "subnet-b"},
			want:  "vpcPeering (link -> subnet-b)",
		},
		{
			name:  "vpcPeering without resolved subnet",
			route: topology.RouteSummary{Type: "vpcPeering", VpcPeering: "link"},
			want:  "vpcPeering (link)",
		},
		{
			name:  "transitGateway with resolved route table",
			route: topology.RouteSummary{Type: "transitGateway", TransitGateway: "hub", TransitGatewayRouteTable: "hub-spokes"},
			want:  "transitGateway (hub -> hub-spokes)",
		},
		{
			name:  "transitGateway without resolved route table",
			route: topology.RouteSummary{Type: "transitGateway", TransitGateway: "hub"},
			want:  "transitGateway (hub)",
		},
		{
			name:  "service",
			route: topology.RouteSummary{Type: "service"},
			want:  "service",
		},
		{
			name:  "unknown type falls back to the raw name",
			route: topology.RouteSummary{Type: "somethingNew"},
			want:  "somethingNew",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatRouteVia(tc.route); got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}
