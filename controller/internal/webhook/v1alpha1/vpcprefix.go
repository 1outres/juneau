/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	// vpcPrefixMinBits and vpcPrefixMaxBits bound the prefix length a
	// Vpc-scoped network may carry. Wider than /16 eats too much of the
	// Vpc, narrower than /28 leaves too few addresses to be useful.
	vpcPrefixMinBits = 16
	vpcPrefixMaxBits = 28
)

// vpcPrefix is one prefix that lives inside a Vpc. Subnet and L2Network
// both declare one, and every overlap check reads this view, so the two
// kinds always see each other's prefixes.
type vpcPrefix struct {
	kind string
	name string
	vpc  string
	raw  string
	cidr *net.IPNet
}

// subnetVpcPrefix reads the prefix a Subnet declares. cidr is nil when
// spec.cidr does not parse; the caller has already reported that.
func subnetVpcPrefix(subnet *juneauv1alpha1.Subnet) vpcPrefix {
	return newVpcPrefix("Subnet", subnet.Name, subnet.Spec.Vpc, subnet.Spec.CIDR)
}

// l2NetworkVpcPrefix reads the prefix an L2Network declares. An
// L2Network may declare none, in which case cidr is nil and no overlap
// check applies to it.
func l2NetworkVpcPrefix(l2 *juneauv1alpha1.L2Network) vpcPrefix {
	return newVpcPrefix("L2Network", l2.Name, l2.Spec.Vpc, l2.Spec.CIDR)
}

func newVpcPrefix(kind, name, vpc, raw string) vpcPrefix {
	prefix := vpcPrefix{kind: kind, name: name, vpc: vpc, raw: raw}
	if raw == "" {
		return prefix
	}
	if _, cidr, err := net.ParseCIDR(raw); err == nil {
		prefix.cidr = cidr
	}
	return prefix
}

func (p vpcPrefix) isSame(other vpcPrefix) bool {
	return p.kind == other.kind && p.name == other.name
}

// validateVpcPrefixCIDR checks the shape of a Vpc-scoped prefix: IPv4
// only, and a prefix length Juneau can build a segment out of.
func validateVpcPrefixCIDR(cidr string, path *field.Path) field.ErrorList {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return field.ErrorList{field.Invalid(path, cidr, "must be a valid IPv4 CIDR")}
	}

	if ipnet.IP.To4() == nil {
		return field.ErrorList{field.Invalid(path, cidr, "only IPv4 CIDR blocks are supported")}
	}

	ones, _ := ipnet.Mask.Size()
	if ones < vpcPrefixMinBits || ones > vpcPrefixMaxBits {
		return field.ErrorList{field.Invalid(path, cidr,
			fmt.Sprintf("CIDR prefix length must be between /%d and /%d", vpcPrefixMinBits, vpcPrefixMaxBits))}
	}

	return nil
}

// validateVpcPrefixOverlaps runs every overlap check a prefix inside a
// Vpc has to pass: against the other networks of its own Vpc, against
// the networks it can reach over a VpcPeering or a shared
// TransitGatewayRouteTable, against every endpoint pool it can reach,
// and against the cluster Service CIDR.
//
// A claim without a parsable CIDR passes: it either declares none, or
// the shape check has already reported it.
func validateVpcPrefixOverlaps(ctx context.Context, c client.Reader, serviceCIDR *net.IPNet, claim vpcPrefix, path *field.Path) (field.ErrorList, error) {
	if claim.cidr == nil {
		return nil, nil
	}

	peerings, err := listPeeredVpcs(ctx, c, claim.vpc)
	if err != nil {
		return nil, err
	}
	reachable, err := listTransitGatewayReachableVpcs(ctx, c, claim.vpc)
	if err != nil {
		return nil, err
	}

	var errs field.ErrorList

	networkErrs, err := validateVpcPrefixNetworkOverlap(ctx, c, claim, peerings, reachable, path)
	if err != nil {
		return nil, err
	}
	errs = append(errs, networkErrs...)

	poolErrs, err := validateVpcPrefixEndpointPoolOverlap(ctx, c, claim, peerings, reachable, path)
	if err != nil {
		return nil, err
	}
	errs = append(errs, poolErrs...)

	serviceErrs, err := validateVpcPrefixServiceCIDROverlap(ctx, c, claim, serviceCIDR, path)
	if err != nil {
		return nil, err
	}
	return append(errs, serviceErrs...), nil
}

// validateVpcPrefixNetworkOverlap rejects a prefix that overlaps
// another Subnet or L2Network the claimant's Vpc can reach. A route
// resolves to exactly one destination VNI, so an address that exists on
// both sides has no single correct answer.
func validateVpcPrefixNetworkOverlap(ctx context.Context, c client.Reader, claim vpcPrefix, peerings, reachable map[string]string, path *field.Path) (field.ErrorList, error) {
	existing, err := listVpcPrefixes(ctx, c)
	if err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for _, other := range existing {
		if other.isSame(claim) || other.cidr == nil || !cidrsOverlap(claim.cidr, other.cidr) {
			continue
		}
		switch {
		case other.vpc == claim.vpc:
			errs = append(errs, field.Invalid(path, claim.raw,
				fmt.Sprintf("overlaps with existing %s %q CIDR %q in Vpc %q",
					other.kind, other.name, other.raw, claim.vpc)))
		case peerings[other.vpc] != "":
			errs = append(errs, field.Invalid(path, claim.raw,
				fmt.Sprintf("overlaps with %s %q CIDR %q in Vpc %q, which is peered by VpcPeering %q",
					other.kind, other.name, other.raw, other.vpc, peerings[other.vpc])))
		case reachable[other.vpc] != "":
			errs = append(errs, field.Invalid(path, claim.raw,
				fmt.Sprintf("overlaps with %s %q CIDR %q in Vpc %q, which is reachable through TransitGatewayRouteTable %q",
					other.kind, other.name, other.raw, other.vpc, reachable[other.vpc])))
		}
	}
	return errs, nil
}

// validateVpcPrefixEndpointPoolOverlap rejects a prefix that overlaps a
// Vpc endpoint pool. Inside its own Vpc the network would swallow the
// VIPs, which are reached through the Vpc gateway and have no arp_table
// entry. Across a peering or a shared TransitGatewayRouteTable the FIB
// would hold the pool route and this network's route for one prefix.
func validateVpcPrefixEndpointPoolOverlap(ctx context.Context, c client.Reader, claim vpcPrefix, peerings, reachable map[string]string, path *field.Path) (field.ErrorList, error) {
	var vpcList juneauv1alpha1.VpcList
	if err := c.List(ctx, &vpcList); err != nil {
		return nil, err
	}

	var errs field.ErrorList
	for i := range vpcList.Items {
		vpc := &vpcList.Items[i]

		var reach string
		switch {
		case vpc.Name == claim.vpc:
			reach = fmt.Sprintf("of its own Vpc %q", vpc.Name)
		case peerings[vpc.Name] != "":
			reach = fmt.Sprintf("of Vpc %q, which is peered by VpcPeering %q", vpc.Name, peerings[vpc.Name])
		case reachable[vpc.Name] != "":
			reach = fmt.Sprintf("of Vpc %q, which is reachable through TransitGatewayRouteTable %q", vpc.Name, reachable[vpc.Name])
		default:
			continue
		}

		for _, entry := range vpc.Spec.EndpointPool.Cidrs() {
			_, poolCIDR, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if cidrsOverlap(claim.cidr, poolCIDR) {
				errs = append(errs, field.Invalid(path, claim.raw,
					fmt.Sprintf("overlaps with endpoint pool CIDR %q %s", entry, reach)))
			}
		}
	}

	return errs, nil
}

// validateVpcPrefixServiceCIDROverlap rejects a prefix that overlaps the
// cluster Service CIDR while its Vpc has Service routing enabled.
// Without this check workload addresses could collide with ClusterIPs
// and the data plane could not tell them apart.
func validateVpcPrefixServiceCIDROverlap(ctx context.Context, c client.Reader, claim vpcPrefix, serviceCIDR *net.IPNet, path *field.Path) (field.ErrorList, error) {
	if serviceCIDR == nil {
		return nil, nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := c.Get(ctx, client.ObjectKey{Name: claim.vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	if !vpc.Spec.ServiceEnabled() {
		return nil, nil
	}

	if cidrsOverlap(claim.cidr, serviceCIDR) {
		return field.ErrorList{field.Invalid(path, claim.raw,
			fmt.Sprintf("overlaps with Service CIDR %q while Vpc %q has Service routing enabled", serviceCIDR.String(), claim.vpc))}, nil
	}

	return nil, nil
}

// listVpcPrefixes returns every prefix already declared in the cluster,
// across both kinds that declare one.
func listVpcPrefixes(ctx context.Context, c client.Reader) ([]vpcPrefix, error) {
	var subnetList juneauv1alpha1.SubnetList
	if err := c.List(ctx, &subnetList); err != nil {
		return nil, err
	}
	var l2List juneauv1alpha1.L2NetworkList
	if err := c.List(ctx, &l2List); err != nil {
		return nil, err
	}

	out := make([]vpcPrefix, 0, len(subnetList.Items)+len(l2List.Items))
	for i := range subnetList.Items {
		out = append(out, subnetVpcPrefix(&subnetList.Items[i]))
	}
	for i := range l2List.Items {
		out = append(out, l2NetworkVpcPrefix(&l2List.Items[i]))
	}
	return out, nil
}

// listPeeredVpcs returns the Vpcs peered with vpcName, mapped to the
// VpcPeering that connects them.
func listPeeredVpcs(ctx context.Context, c client.Reader, vpcName string) (map[string]string, error) {
	var peeringList juneauv1alpha1.VpcPeeringList
	if err := c.List(ctx, &peeringList); err != nil {
		return nil, err
	}

	peerings := map[string]string{}
	for i := range peeringList.Items {
		peering := &peeringList.Items[i]
		peer, ok := peering.Spec.PeerOf(vpcName)
		if !ok {
			continue
		}
		if _, seen := peerings[peer]; !seen {
			peerings[peer] = peering.Name
		}
	}

	return peerings, nil
}

// listTransitGatewayReachableVpcs returns the Vpcs whose prefixes reach
// vpcName through a shared TransitGatewayRouteTable, mapped to the route
// table that carries them.
func listTransitGatewayReachableVpcs(ctx context.Context, c client.Reader, vpcName string) (map[string]string, error) {
	var attachmentList juneauv1alpha1.TransitGatewayAttachmentList
	if err := c.List(ctx, &attachmentList); err != nil {
		return nil, err
	}

	var routeTables []string
	for i := range attachmentList.Items {
		if attachmentList.Items[i].Spec.Vpc != vpcName {
			continue
		}
		routeTables = append(routeTables, attachmentList.Items[i].Spec.RouteTables()...)
	}
	if len(routeTables) == 0 {
		return nil, nil
	}

	return transitGatewayReachableVpcs("", vpcName, routeTables, attachmentList.Items), nil
}

func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}
