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
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// supportedLoadBalancerProtocols enumerates the L4 protocols Juneau's
// LoadBalancer dataplane is able to forward in the initial release.
// SCTP and any future protocols are rejected at admission time so the
// failure surfaces to the user instead of as silent traffic blackholes.
var supportedLoadBalancerProtocols = map[corev1.Protocol]struct{}{
	corev1.ProtocolTCP: {},
	corev1.ProtocolUDP: {},
}

// IsJuneauManagedLoadBalancer reports whether a Service is in scope
// for Juneau's LoadBalancer reconciler.
//
// A Service is in scope iff:
//   - spec.type is LoadBalancer
//   - spec.loadBalancerClass exactly matches the Juneau class
//
// Empty loadBalancerClass is intentionally treated as out-of-scope so
// that Juneau coexists with cloud-provider integrations that race for
// classless LoadBalancer ownership. Operators wanting Juneau to own
// classless Services must opt in by setting the class explicitly.
func IsJuneauManagedLoadBalancer(svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}
	if svc.Spec.LoadBalancerClass == nil {
		return false
	}
	return *svc.Spec.LoadBalancerClass == juneauv1alpha1.LoadBalancerClass
}

// loadBalancerAnnotationsChanged reports whether the LoadBalancer-
// related annotations or the loadBalancerClass differ between two
// Services. Used by ValidateUpdate to decide whether re-validation is
// needed.
func loadBalancerAnnotationsChanged(oldSvc, newSvc *corev1.Service) bool {
	if !equalLoadBalancerClass(oldSvc, newSvc) {
		return true
	}
	if oldSvc.Spec.Type != newSvc.Spec.Type {
		return true
	}
	if !equalExternalTrafficPolicy(oldSvc, newSvc) {
		return true
	}
	if oldSvc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork] !=
		newSvc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork] {
		return true
	}
	if oldSvc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP] !=
		newSvc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP] {
		return true
	}
	return !equalServicePorts(oldSvc.Spec.Ports, newSvc.Spec.Ports)
}

func equalLoadBalancerClass(a, b *corev1.Service) bool {
	switch {
	case a.Spec.LoadBalancerClass == nil && b.Spec.LoadBalancerClass == nil:
		return true
	case a.Spec.LoadBalancerClass == nil || b.Spec.LoadBalancerClass == nil:
		return false
	default:
		return *a.Spec.LoadBalancerClass == *b.Spec.LoadBalancerClass
	}
}

func equalExternalTrafficPolicy(a, b *corev1.Service) bool {
	return a.Spec.ExternalTrafficPolicy == b.Spec.ExternalTrafficPolicy
}

func equalServicePorts(a, b []corev1.ServicePort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name ||
			a[i].Protocol != b[i].Protocol ||
			a[i].Port != b[i].Port ||
			a[i].TargetPort != b[i].TargetPort {
			return false
		}
	}
	return true
}

// validateLoadBalancer returns the field errors raised by Juneau's
// LoadBalancer-specific admission rules. The function is a no-op for
// Services that are not in scope for Juneau (different class, empty
// class, or non-LoadBalancer type), so callers can invoke it
// unconditionally.
func (v *ServiceCustomValidator) validateLoadBalancer(ctx context.Context, svc *corev1.Service) (field.ErrorList, error) {
	if !IsJuneauManagedLoadBalancer(svc) {
		return nil, nil
	}

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	annPath := field.NewPath("metadata", "annotations")

	// externalTrafficPolicy=Local is required: Juneau's source-
	// preserving LoadBalancer model only forwards from ingress nodes
	// that hold a local backend. Cluster traffic policy needs
	// distributed conntrack / DSR machinery that the initial release
	// does not provide.
	if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
		errs = append(errs, field.Invalid(
			specPath.Child("externalTrafficPolicy"),
			string(svc.Spec.ExternalTrafficPolicy),
			"Juneau-managed LoadBalancer Services must set externalTrafficPolicy=Local",
		))
	}

	// External network annotation is required and must reference an
	// existing ExternalNetwork. The pool/IP-range check happens later
	// in the controller (it requires resolving AddressPools and is
	// not cheap to do at admission time for every update); we only
	// confirm the resource exists here.
	externalNetworkPath := annPath.Key(juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork)
	externalNetwork := svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork]
	switch {
	case externalNetwork == "":
		errs = append(errs, field.Required(
			externalNetworkPath,
			"Juneau-managed LoadBalancer Services must set the load-balancer-external-network annotation",
		))
	case len(apivalidation.NameIsDNSSubdomain(externalNetwork, false)) != 0:
		errs = append(errs, field.Invalid(
			externalNetworkPath,
			externalNetwork,
			"value must be a valid DNS subdomain",
		))
	default:
		var en juneauv1alpha1.ExternalNetwork
		if err := v.Get(ctx, client.ObjectKey{Name: externalNetwork}, &en); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(
					externalNetworkPath,
					externalNetwork,
					"referenced ExternalNetwork does not exist",
				))
			} else {
				return nil, err
			}
		}
	}

	// Optional requested-IP annotation must be a syntactically valid
	// IPv4 address. Pool membership is checked by the controller once
	// the AddressPools backing the ExternalNetwork are resolved.
	requestedIPPath := annPath.Key(juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP)
	if requested := svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP]; requested != "" {
		addr, err := netip.ParseAddr(requested)
		switch {
		case err != nil:
			errs = append(errs, field.Invalid(
				requestedIPPath,
				requested,
				"requested IP must be a valid IP address",
			))
		case !addr.Is4():
			errs = append(errs, field.Invalid(
				requestedIPPath,
				requested,
				"requested IP must be IPv4 in the initial release",
			))
		}
	}

	// Per-port checks: at least one port (already enforced by the
	// core Service validator) and only supported protocols.
	portsPath := specPath.Child("ports")
	for i, p := range svc.Spec.Ports {
		if _, ok := supportedLoadBalancerProtocols[p.Protocol]; !ok {
			errs = append(errs, field.NotSupported(
				portsPath.Index(i).Child("protocol"),
				string(p.Protocol),
				[]string{string(corev1.ProtocolTCP), string(corev1.ProtocolUDP)},
			))
		}
	}

	return errs, nil
}
