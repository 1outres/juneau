package v1alpha1

import (
	"context"
	"fmt"
	"net"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (v *RouteTableCustomValidator) validateVPNRoute(ctx context.Context, table *juneau.RouteTable, route juneau.Route, path *field.Path) (field.ErrorList, error) {
	var errs field.ErrorList
	ref := route.Via.VPN
	refPath := path.Child("via", "vpn")
	if ref == nil {
		return field.ErrorList{field.Required(refPath, "VPN namespace and name are required")}, nil
	}
	if ref.Namespace == "" {
		errs = append(errs, field.Required(refPath.Child("namespace"), "namespace is required"))
	} else if validation.IsDNS1123Subdomain(ref.Namespace) != nil {
		errs = append(errs, field.Invalid(refPath.Child("namespace"), ref.Namespace, "must be a DNS name"))
	}
	if ref.Name == "" {
		errs = append(errs, field.Required(refPath.Child("name"), "name is required"))
	} else if validation.IsDNS1123Subdomain(ref.Name) != nil {
		errs = append(errs, field.Invalid(refPath.Child("name"), ref.Name, "must be a DNS name"))
	}
	if route.Via.Endpoint != "" {
		errs = append(errs, field.Forbidden(path.Child("via", "endpointName"), "endpointName must be empty for a VPN route"))
	}
	if route.Via.NATGateway != "" {
		errs = append(errs, field.Forbidden(path.Child("via", "natGateway"), "natGateway must be empty for a VPN route"))
	}
	if route.Via.VpcPeering != "" {
		errs = append(errs, field.Forbidden(path.Child("via", "vpcPeering"), "vpcPeering must be empty for a VPN route"))
	}
	if route.Via.TransitGateway != "" {
		errs = append(errs, field.Forbidden(path.Child("via", "transitGateway"), "transitGateway must be empty for a VPN route"))
	}
	if !shouldCheckReferences(table) {
		return errs, nil
	}
	if ref.Namespace != "" && ref.Name != "" && validation.IsDNS1123Subdomain(ref.Namespace) == nil && validation.IsDNS1123Subdomain(ref.Name) == nil {
		var vpn juneau.VPN
		if err := v.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &vpn); err != nil {
			if apierrors.IsNotFound(err) {
				errs = append(errs, field.Invalid(refPath, ref, "VPN does not exist"))
			} else {
				return nil, err
			}
		} else if vpn.Spec.Vpc != table.Spec.Vpc || !vpn.DeletionTimestamp.IsZero() {
			errs = append(errs, field.Invalid(refPath, ref, "VPN must belong to the RouteTable Vpc and must not be deleting"))
		}
	}
	_, cidr, err := net.ParseCIDR(route.Dst)
	if err != nil || cidr.IP.To4() == nil || cidr.String() != route.Dst {
		return errs, nil
	}
	var vpc juneau.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: table.Spec.Vpc}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			errs = append(errs, field.Invalid(field.NewPath("spec", "vpc"), table.Spec.Vpc, "Vpc does not exist"))
			return errs, nil
		}
		return nil, err
	}
	if route.Dst == "0.0.0.0/0" {
		return errs, nil
	}
	prefixes, err := listVpcPrefixes(ctx, v.Reader)
	if err != nil {
		return nil, err
	}
	peers, err := listPeeredVpcs(ctx, v.Reader, table.Spec.Vpc)
	if err != nil {
		return nil, err
	}
	reachable, err := listTransitGatewayReachableVpcs(ctx, v.Reader, table.Spec.Vpc)
	if err != nil {
		return nil, err
	}
	for _, prefix := range prefixes {
		if prefix.cidr != nil && (prefix.vpc == table.Spec.Vpc || peers[prefix.vpc] != "" || reachable[prefix.vpc] != "") && cidrsOverlap(cidr, prefix.cidr) {
			errs = append(errs, field.Invalid(path.Child("dst"), route.Dst, fmt.Sprintf("overlaps reachable %s %q CIDR %q", prefix.kind, prefix.name, prefix.raw)))
		}
	}
	for _, pool := range vpc.Spec.EndpointPool.Cidrs() {
		_, network, err := net.ParseCIDR(pool)
		if err == nil && cidrsOverlap(cidr, network) {
			errs = append(errs, field.Invalid(path.Child("dst"), route.Dst, fmt.Sprintf("overlaps reachable VpcEndpoint pool %q", pool)))
		}
	}
	if vpc.Spec.ServiceEnabled() {
		if v.ServiceCIDR == nil {
			return nil, fmt.Errorf("Service CIDR is required to validate VPN routes in Vpc %q", vpc.Name)
		}
		if cidrsOverlap(cidr, v.ServiceCIDR) {
			errs = append(errs, field.Invalid(path.Child("dst"), route.Dst, fmt.Sprintf("overlaps reachable Service CIDR %q", v.ServiceCIDR)))
		}
		var services corev1.ServiceList
		if err := v.List(ctx, &services); err != nil {
			return nil, err
		}
		for _, svc := range services.Items {
			if serviceVpc(&svc) != vpc.Name || svc.Spec.Type == corev1.ServiceTypeExternalName {
				continue
			}
			for _, raw := range svc.Spec.ExternalIPs {
				ip := net.ParseIP(raw)
				if ip != nil && ip.To4() != nil && cidr.Contains(ip) {
					errs = append(errs, field.Invalid(path.Child("dst"), route.Dst, fmt.Sprintf("overlaps reachable Service %s/%s external IP %s", svc.Namespace, svc.Name, raw)))
				}
			}
		}
	}
	return errs, nil
}
