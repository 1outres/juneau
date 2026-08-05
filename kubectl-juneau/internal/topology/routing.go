package topology

import (
	"context"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// resolveRouteTableForSubnet returns the RouteTable that governs
// traffic from the given Subnet, plus a flag indicating whether the
// resolved table is the Vpc's main table (true) or a Subnet-level
// override (false).
//
// MIRRORS controller-side resolution: when subnet.spec.routeTable is
// set, that one wins; otherwise vpc.status.mainRouteTable is used. If
// either reference dangles or the corresponding object is missing,
// the function returns (nil, isMain, nil) — the caller decides how to
// surface that absence in the presenter.
//
// The function does not return errors for "object not found" because
// View follows the (nil, nil) convention for IsNotFound.
func resolveRouteTableForSubnet(
	ctx context.Context,
	v View,
	subnet *juneauv1alpha1.Subnet,
	vpc *juneauv1alpha1.Vpc,
) (*juneauv1alpha1.RouteTable, bool, error) {
	if subnet == nil {
		return nil, false, nil
	}
	if subnet.Spec.RouteTable != "" {
		rt, err := v.RouteTable(ctx, subnet.Spec.RouteTable)
		if err != nil {
			return nil, false, err
		}
		return rt, false, nil
	}
	if vpc == nil || vpc.Status.MainRouteTable == "" {
		return nil, true, nil
	}
	rt, err := v.RouteTable(ctx, vpc.Status.MainRouteTable)
	if err != nil {
		return nil, true, err
	}
	return rt, true, nil
}

// summariseRouteTable converts a juneauv1alpha1.RouteTable into the
// presenter-friendly RouteTableSummary, preferring status.routes (what
// the controller actually committed) over spec.routes.
func summariseRouteTable(rt *juneauv1alpha1.RouteTable, isMain bool) *RouteTableSummary {
	if rt == nil {
		return nil
	}
	src := rt.Status.Routes
	if len(src) == 0 {
		src = rt.Spec.Routes
	}
	out := &RouteTableSummary{
		Name:   rt.Name,
		IsMain: isMain,
		Routes: make([]RouteSummary, 0, len(src)),
	}
	for _, r := range src {
		out.Routes = append(out.Routes, RouteSummary{
			Dst:                      r.Dst,
			Type:                     string(r.Via.Type),
			Subnet:                   r.Subnet,
			Endpoint:                 r.Via.Endpoint,
			NATGateway:               r.Via.NATGateway,
			VpcPeering:               r.Via.VpcPeering,
			TransitGateway:           r.Via.TransitGateway,
			TransitGatewayRouteTable: r.TransitGatewayRouteTable,
		})
	}
	return out
}

// summariseNetworkACL distils an ACL into its presenter view. Returns
// nil for nil input so the caller can chain summariseNetworkACL(view.NetworkACL(...))
// without nil checks.
func summariseNetworkACL(acl *juneauv1alpha1.NetworkACL) *NetworkACLSummary {
	if acl == nil {
		return nil
	}
	return &NetworkACLSummary{
		Name:            acl.Name,
		ACLID:           acl.Status.ACLID,
		IngressRules:    acl.Status.IngressRuleCount,
		EgressRules:     acl.Status.EgressRuleCount,
		HasIngressRules: acl.Status.HasIngressRules,
		HasEgressRules:  acl.Status.HasEgressRules,
		RulesetVersion:  acl.Status.RulesetVersion,
	}
}

// summariseSecurityGroup distils an SG into its presenter view.
func summariseSecurityGroup(sg *juneauv1alpha1.SecurityGroup) SecurityGroupSummary {
	return SecurityGroupSummary{
		Name:           sg.Name,
		GroupID:        sg.Status.GroupID,
		IngressRules:   sg.Status.IngressRuleCount,
		EgressRules:    sg.Status.EgressRuleCount,
		HasEgressRules: sg.Status.HasEgressRules,
		RulesetVersion: sg.Status.RulesetVersion,
	}
}

// summariseNATGateway distils a NATGateway into its presenter view.
func summariseNATGateway(ng *juneauv1alpha1.NATGateway) NATGatewaySummary {
	return NATGatewaySummary{
		Name:            ng.Name,
		GatewayID:       ng.Status.GatewayID,
		ExternalNetwork: ng.Spec.ExternalNetwork,
	}
}
