package describe

import (
	"fmt"

	"github.com/1outres/juneau/kubectl-juneau/internal/topology"
)

// displayOrDash returns "-" for empty strings so absent fields render
// consistently across presenters. Empty strings in a tree are
// ambiguous; "-" reads as "intentionally absent".
func displayOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// formatRouteVia renders a RouteSummary's via clause for the tree
// presenters. Centralising the format here keeps subnet / pod / nic
// outputs identical for the same route.
func formatRouteVia(r topology.RouteSummary) string {
	switch r.Type {
	case "connected":
		if r.Subnet != "" {
			return fmt.Sprintf("connected (%s)", r.Subnet)
		}
		return "connected"
	case "endpoint":
		return fmt.Sprintf("endpoint (%s)", displayOrDash(r.Endpoint))
	case "internetGateway":
		return "internetGateway"
	case "natGateway":
		return fmt.Sprintf("natGateway (%s)", displayOrDash(r.NATGateway))
	case "vpcPeering":
		// The peering names the path and the peer Subnet names where the
		// packet actually lands, so show both once the controller has
		// resolved the second one.
		if r.Subnet != "" {
			return fmt.Sprintf("vpcPeering (%s -> %s)", displayOrDash(r.VpcPeering), r.Subnet)
		}
		return fmt.Sprintf("vpcPeering (%s)", displayOrDash(r.VpcPeering))
	case "transitGateway":
		if r.TransitGatewayRouteTable != "" {
			return fmt.Sprintf("transitGateway (%s -> %s)", displayOrDash(r.TransitGateway), r.TransitGatewayRouteTable)
		}
		return fmt.Sprintf("transitGateway (%s)", displayOrDash(r.TransitGateway))
	case "service":
		return "service"
	}
	if r.Type == "" {
		return "-"
	}
	return r.Type
}
