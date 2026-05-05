package topology

import "context"

// ResolveSubnetContext walks a single Subnet to its Vpc, RouteTable,
// NetworkACL and the NetworkInterfaces hosted in it.
func ResolveSubnetContext(ctx context.Context, v View, name string) (*SubnetContext, error) {
	out := &SubnetContext{Name: name}

	subnet, err := v.Subnet(ctx, name)
	if err != nil {
		return nil, err
	}
	out.Subnet = subnet
	if subnet == nil {
		return out, nil
	}

	if subnet.Spec.Vpc != "" {
		vpc, err := v.Vpc(ctx, subnet.Spec.Vpc)
		if err != nil {
			return nil, err
		}
		out.Vpc = vpc

		rt, isMain, err := resolveRouteTableForSubnet(ctx, v, subnet, vpc)
		if err != nil {
			return nil, err
		}
		out.RouteTable = summariseRouteTable(rt, isMain)
		out.RouteTableIsMain = isMain
	}

	if subnet.Spec.NetworkACL != "" {
		acl, err := v.NetworkACL(ctx, subnet.Spec.NetworkACL)
		if err != nil {
			return nil, err
		}
		out.NetworkACL = summariseNetworkACL(acl)
	}

	nics, err := v.NetworkInterfacesBySubnet(ctx, name)
	if err != nil {
		return nil, err
	}
	out.Interfaces = nics
	return out, nil
}
