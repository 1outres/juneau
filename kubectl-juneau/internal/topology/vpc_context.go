package topology

import "context"

// ResolveVpcContext gathers everything that hangs off a Vpc: its
// Subnets, RouteTables (with the main flag set on the right one),
// SecurityGroups, NetworkACLs and NATGateways.
func ResolveVpcContext(ctx context.Context, v View, name string) (*VpcContext, error) {
	out := &VpcContext{Name: name}

	vpc, err := v.Vpc(ctx, name)
	if err != nil {
		return nil, err
	}
	out.Vpc = vpc
	if vpc == nil {
		return out, nil
	}

	subnets, err := v.SubnetsByVpc(ctx, name)
	if err != nil {
		return nil, err
	}
	out.Subnets = subnets

	rts, err := v.RouteTablesByVpc(ctx, name)
	if err != nil {
		return nil, err
	}
	mainName := vpc.Status.MainRouteTable
	out.RouteTables = make([]RouteTableSummary, 0, len(rts))
	for i := range rts {
		isMain := mainName != "" && rts[i].Name == mainName
		summary := summariseRouteTable(&rts[i], isMain)
		if summary != nil {
			out.RouteTables = append(out.RouteTables, *summary)
		}
	}

	sgs, err := v.SecurityGroupsByVpc(ctx, name)
	if err != nil {
		return nil, err
	}
	out.SecurityGroups = make([]SecurityGroupSummary, 0, len(sgs))
	for i := range sgs {
		out.SecurityGroups = append(out.SecurityGroups, summariseSecurityGroup(&sgs[i]))
	}

	acls, err := v.NetworkACLsByVpc(ctx, name)
	if err != nil {
		return nil, err
	}
	out.NetworkACLs = make([]NetworkACLSummary, 0, len(acls))
	for i := range acls {
		summary := summariseNetworkACL(&acls[i])
		if summary != nil {
			out.NetworkACLs = append(out.NetworkACLs, *summary)
		}
	}

	natgws, err := v.NATGatewaysByVpc(ctx, name)
	if err != nil {
		return nil, err
	}
	out.NATGateways = make([]NATGatewaySummary, 0, len(natgws))
	for i := range natgws {
		out.NATGateways = append(out.NATGateways, summariseNATGateway(&natgws[i]))
	}

	return out, nil
}
