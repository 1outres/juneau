package topology

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

// ResolveServiceContext returns the Vpc binding (annotation), shared
// flag, and per-backend reachability summary for a Service. The
// SameVpc flag on each backend is computed against the Service's owning
// Vpc so cross-Vpc Pod misplacement is visible at a glance.
func ResolveServiceContext(ctx context.Context, v View, namespace, name string) (*ServiceContext, error) {
	out := &ServiceContext{Namespace: namespace, Name: name}

	svc, err := v.Service(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	out.Service = svc
	if svc == nil {
		return out, nil
	}

	out.VpcName = vpcNameFromServiceAnnotations(svc)
	out.Shared = isSharedService(svc)

	if out.VpcName != "" {
		vpc, err := v.Vpc(ctx, out.VpcName)
		if err != nil {
			return nil, err
		}
		out.Vpc = vpc
	}

	slices, err := v.EndpointSlicesForService(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	out.Backends, err = collectServiceBackends(ctx, v, slices, out.VpcName, out.Shared)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func vpcNameFromServiceAnnotations(svc *corev1.Service) string {
	if v := svc.Annotations[AnnotationServiceVpc]; v != "" {
		return v
	}
	return DefaultVpcName
}

func isSharedService(svc *corev1.Service) bool {
	v := strings.TrimSpace(svc.Annotations[AnnotationServiceShared])
	return strings.EqualFold(v, "true")
}

// collectServiceBackends translates EndpointSlice addresses into
// ServiceBackend rows by joining each address back to a Pod (via
// targetRef.kind=Pod) and that Pod's NetworkInterface → Subnet → Vpc
// chain.
//
// Missing references are tolerated: a backend whose target Pod has
// been deleted still surfaces as a row with empty Pod/Vpc fields and
// SameVpc=false so the operator sees the dangling endpoint.
func collectServiceBackends(
	ctx context.Context,
	v View,
	slices []discoveryv1.EndpointSlice,
	serviceVpc string,
	shared bool,
) ([]ServiceBackend, error) {
	var out []ServiceBackend
	for _, slice := range slices {
		for _, ep := range slice.Endpoints {
			for _, addr := range ep.Addresses {
				b := ServiceBackend{Address: addr}
				if ep.NodeName != nil {
					b.NodeName = *ep.NodeName
				}
				if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
					b.PodNamespace = ep.TargetRef.Namespace
					b.PodName = ep.TargetRef.Name
					if err := fillBackendFromPod(ctx, v, &b); err != nil {
						return nil, err
					}
				}
				b.SameVpc = backendVpcMatches(b.VpcName, serviceVpc, shared)
				out = append(out, b)
			}
		}
	}
	return out, nil
}

// fillBackendFromPod resolves the Pod's owning Subnet/Vpc through its
// NetworkInterface and stamps the backend row.
func fillBackendFromPod(ctx context.Context, v View, b *ServiceBackend) error {
	nics, err := v.NetworkInterfacesByPod(ctx, b.PodNamespace, b.PodName)
	if err != nil {
		return err
	}
	if len(nics) == 0 {
		return nil
	}
	nic := nics[0]
	b.SubnetName = nic.Spec.Subnet
	if nic.Spec.Subnet == "" {
		return nil
	}
	subnet, err := v.Subnet(ctx, nic.Spec.Subnet)
	if err != nil {
		return err
	}
	if subnet != nil {
		b.VpcName = subnet.Spec.Vpc
	}
	return nil
}

// backendVpcMatches encodes the reachability oracle for a Service
// backend. A non-shared Service requires the backend's owning Vpc to
// equal the Service's. A shared Service tolerates default-Vpc backends
// regardless of caller.
func backendVpcMatches(backendVpc, serviceVpc string, shared bool) bool {
	if backendVpc == "" || serviceVpc == "" {
		return false
	}
	if shared {
		return backendVpc == DefaultVpcName
	}
	return backendVpc == serviceVpc
}
