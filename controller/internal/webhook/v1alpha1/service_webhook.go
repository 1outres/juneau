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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	// ServiceAnnotationVpc selects which Juneau Vpc owns the Service.
	// Absent annotation implies the default Vpc.
	ServiceAnnotationVpc = "juneau.loutres.me/vpc"
	// ServiceAnnotationSubnet is intentionally rejected; Service is a
	// VPC-scoped concept and cannot be tied to a single Subnet.
	ServiceAnnotationSubnet = "juneau.loutres.me/subnet"
	// ServiceAnnotationShared opts a Service in to cross-Vpc visibility.
	// The owner Vpc must have spec.service.provider.natSourceSubnet
	// configured for this annotation to be valid.
	ServiceAnnotationShared = "juneau.loutres.me/shared-service"
	// ServiceAnnotationAllowedConsumerVpcs whitelists the caller Vpcs
	// that may reach the shared Service. Comma-separated Vpc names;
	// when absent every consume-enabled Vpc is permitted. Each listed
	// Vpc must exist and have spec.service.consume=true.
	ServiceAnnotationAllowedConsumerVpcs = "juneau.loutres.me/shared-service-allowed-consumer-vpcs"

	defaultServiceVpc = "default"
)

// nolint:unused
var servicelog = logf.Log.WithName("service-resource")

// SetupServiceWebhookWithManager registers the webhook for core/v1.Service
// in the manager. It validates Juneau-specific annotations on Service
// objects and rejects Services bound to a Vpc that does not have
// Service routing enabled.
func SetupServiceWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Service{}).
		WithValidator(&ServiceCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate--v1-service,mutating=false,failurePolicy=fail,sideEffects=None,groups="",resources=services,verbs=create;update,versions=v1,name=vservice-juneau-loutres-me.kb.io,admissionReviewVersions=v1

// ServiceCustomValidator validates core/v1.Service objects against Juneau
// constraints. Services pointing at a Vpc that does not have Service
// routing enabled are rejected so that no Service is silently
// unreachable.
type ServiceCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &ServiceCustomValidator{}

func (v *ServiceCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("expected a Service object but got %T", obj)
	}

	errs, err := v.validate(ctx, svc)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		return nil, errors.NewInvalid(schema.GroupKind{Kind: "Service"}, svc.Name, errs)
	}

	return nil, nil
}

func (v *ServiceCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	newSvc, ok := newObj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("expected a Service object for newObj but got %T", newObj)
	}
	oldSvc, ok := oldObj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("expected a Service object for oldObj but got %T", oldObj)
	}

	if serviceVpc(newSvc) == serviceVpc(oldSvc) &&
		newSvc.Annotations[ServiceAnnotationSubnet] == oldSvc.Annotations[ServiceAnnotationSubnet] &&
		newSvc.Annotations[ServiceAnnotationShared] == oldSvc.Annotations[ServiceAnnotationShared] &&
		newSvc.Annotations[ServiceAnnotationAllowedConsumerVpcs] == oldSvc.Annotations[ServiceAnnotationAllowedConsumerVpcs] &&
		newSvc.Annotations[juneauv1alpha1.ServiceAnnotationLBExternalNetwork] == oldSvc.Annotations[juneauv1alpha1.ServiceAnnotationLBExternalNetwork] &&
		newSvc.Annotations[juneauv1alpha1.ServiceAnnotationLBRequestedIP] == oldSvc.Annotations[juneauv1alpha1.ServiceAnnotationLBRequestedIP] &&
		loadBalancerClassEqual(newSvc, oldSvc) {
		// Annotations relevant to Juneau are unchanged. Skip
		// re-validation so that pre-existing Services keep working
		// even if the upstream Vpcs / ExternalNetworks later mutate.
		return nil, nil
	}

	errs, err := v.validate(ctx, newSvc)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		return nil, errors.NewInvalid(schema.GroupKind{Kind: "Service"}, newSvc.Name, errs)
	}

	return nil, nil
}

func (v *ServiceCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_ = ctx
	_ = obj
	return nil, nil
}

func (v *ServiceCustomValidator) validate(ctx context.Context, svc *corev1.Service) (field.ErrorList, error) {
	var errs field.ErrorList
	annPath := field.NewPath("metadata", "annotations")

	if _, hasSubnet := svc.Annotations[ServiceAnnotationSubnet]; hasSubnet {
		errs = append(errs, field.Forbidden(annPath.Key(ServiceAnnotationSubnet), "Service is VPC-scoped; specifying a Subnet is not allowed"))
	}

	vpcName := serviceVpc(svc)
	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: vpcName}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			errs = append(errs, field.Invalid(annPath.Key(ServiceAnnotationVpc), vpcName, "referenced Vpc does not exist"))
			return errs, nil
		}
		return nil, err
	}

	if !vpc.Spec.ServiceEnabled() {
		errs = append(errs, field.Invalid(annPath.Key(ServiceAnnotationVpc), vpcName, fmt.Sprintf("Vpc %q does not have Service routing enabled (configure spec.service.consume or spec.service.provider)", vpcName)))
	}

	sharedRequested := isSharedServiceAnnotation(svc.Annotations[ServiceAnnotationShared])
	if sharedRequested && !vpc.Spec.Service.IsProvider() {
		// shared-service requires the owner Vpc to have a NAT source
		// Subnet so per-Node SNAT IPs can be allocated for cross-VPC
		// callers.
		errs = append(errs, field.Invalid(annPath.Key(ServiceAnnotationShared), svc.Annotations[ServiceAnnotationShared], fmt.Sprintf("Vpc %q is not configured as a Service provider (set spec.service.provider.natSourceSubnet)", vpcName)))
	}

	if aclErrs, err := v.validateAllowedConsumers(ctx, svc, sharedRequested, annPath); err != nil {
		return nil, err
	} else {
		errs = append(errs, aclErrs...)
	}

	if lbErrs, err := v.validateLoadBalancer(ctx, svc); err != nil {
		return nil, err
	} else {
		errs = append(errs, lbErrs...)
	}

	return errs, nil
}

// validateLoadBalancer enforces the contract for Services whose
// spec.loadBalancerClass selects this controller. The function is a
// no-op for non-LB Services and for foreign-class LB Services. Errors
// are returned as field.ErrorList so callers can aggregate them with
// the rest of the Service validation surface; transient lookup errors
// (envtest API server hiccups) propagate as ordinary errors.
func (v *ServiceCustomValidator) validateLoadBalancer(ctx context.Context, svc *corev1.Service) (field.ErrorList, error) {
	if svc.Spec.LoadBalancerClass == nil || *svc.Spec.LoadBalancerClass != juneauv1alpha1.ServiceLoadBalancerClass {
		return nil, nil
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		// A non-LoadBalancer type with a Juneau class is logically
		// nonsensical; surface it before allocation churn starts.
		return field.ErrorList{field.Invalid(field.NewPath("spec", "loadBalancerClass"), *svc.Spec.LoadBalancerClass,
			"loadBalancerClass requires spec.type=LoadBalancer")}, nil
	}

	annPath := field.NewPath("metadata", "annotations")
	var errs field.ErrorList

	// The legacy spec.loadBalancerIP has been deprecated upstream and
	// has poorly defined semantics for IP pools. We require operators
	// to set the IP via the dedicated annotation so the LB selector
	// (external-network) and the IP pin live side by side.
	if strings.TrimSpace(svc.Spec.LoadBalancerIP) != "" {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "loadBalancerIP"),
			fmt.Sprintf("use the %q annotation; spec.loadBalancerIP is deprecated and ignored",
				juneauv1alpha1.ServiceAnnotationLBRequestedIP)))
	}

	externalNetworkName := strings.TrimSpace(svc.Annotations[juneauv1alpha1.ServiceAnnotationLBExternalNetwork])
	extNetPath := annPath.Key(juneauv1alpha1.ServiceAnnotationLBExternalNetwork)
	if externalNetworkName == "" {
		errs = append(errs, field.Required(extNetPath,
			fmt.Sprintf("loadBalancerClass=%q requires the %q annotation",
				juneauv1alpha1.ServiceLoadBalancerClass, juneauv1alpha1.ServiceAnnotationLBExternalNetwork)))
		return errs, nil
	}

	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := v.Get(ctx, client.ObjectKey{Name: externalNetworkName}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			errs = append(errs, field.Invalid(extNetPath, externalNetworkName, "ExternalNetwork not found"))
			return errs, nil
		}
		return nil, err
	}

	if externalNetwork.Spec.Type != juneauv1alpha1.ExternalNetworkTypeBGP {
		errs = append(errs, field.Invalid(extNetPath, externalNetworkName,
			fmt.Sprintf("ExternalNetwork %q must be type=bgp (LoadBalancer over ARP is not supported)", externalNetworkName)))
		return errs, nil
	}

	requestedIP := strings.TrimSpace(svc.Annotations[juneauv1alpha1.ServiceAnnotationLBRequestedIP])
	if requestedIP == "" {
		return errs, nil
	}
	reqIPPath := annPath.Key(juneauv1alpha1.ServiceAnnotationLBRequestedIP)

	parsed := net.ParseIP(requestedIP)
	if parsed == nil || parsed.To4() == nil {
		errs = append(errs, field.Invalid(reqIPPath, requestedIP, "must be a valid IPv4 address"))
		return errs, nil
	}

	// Pool containment: walk the pools backing the chosen
	// ExternalNetwork and ensure the pinned IP falls inside one of
	// their CIDRs. This protects users from typos that would otherwise
	// only surface as an AllocationClaim failure later.
	contained, lookupErr := v.requestedIPContainedInPools(ctx, &externalNetwork, parsed.To4())
	if lookupErr != nil {
		return nil, lookupErr
	}
	if !contained {
		errs = append(errs, field.Invalid(reqIPPath, requestedIP,
			fmt.Sprintf("address is outside the AddressPools attached to ExternalNetwork %q", externalNetworkName)))
	}
	return errs, nil
}

func (v *ServiceCustomValidator) requestedIPContainedInPools(ctx context.Context, extNet *juneauv1alpha1.ExternalNetwork, ip net.IP) (bool, error) {
	for _, raw := range extNet.Spec.AddressPools {
		poolName := strings.TrimSpace(raw)
		if poolName == "" {
			continue
		}
		var pool juneauv1alpha1.AddressPool
		if err := v.Get(ctx, client.ObjectKey{Name: poolName}, &pool); err != nil {
			if errors.IsNotFound(err) {
				// Skip missing pools; the LB controller will surface
				// the misconfiguration via a status condition. Webhook
				// validation should not block on transient state.
				continue
			}
			return false, err
		}
		for _, addr := range pool.Spec.Addresses {
			if cidrContains(strings.TrimSpace(addr), ip) {
				return true, nil
			}
		}
	}
	return false, nil
}

// cidrContains reports whether s is a CIDR that contains ip. Values
// that aren't parseable as CIDR or as a single IP/range are treated as
// non-containing rather than as a hard error so a single malformed
// pool entry doesn't fail the entire admission check.
func cidrContains(s string, ip net.IP) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return false
		}
		return ipnet.Contains(ip)
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) != 2 {
			return false
		}
		lo := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		hi := net.ParseIP(strings.TrimSpace(parts[1])).To4()
		ip4 := ip.To4()
		if lo == nil || hi == nil || ip4 == nil {
			return false
		}
		return ipv4LessOrEqual(lo, ip4) && ipv4LessOrEqual(ip4, hi)
	}
	single := net.ParseIP(s)
	return single != nil && single.Equal(ip)
}

func ipv4LessOrEqual(a, b net.IP) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return true
}

func loadBalancerClassEqual(a, b *corev1.Service) bool {
	if a.Spec.LoadBalancerClass == nil && b.Spec.LoadBalancerClass == nil {
		return true
	}
	if a.Spec.LoadBalancerClass == nil || b.Spec.LoadBalancerClass == nil {
		return false
	}
	return *a.Spec.LoadBalancerClass == *b.Spec.LoadBalancerClass
}

// validateAllowedConsumers enforces that every Vpc listed in the
// allowed-consumer-vpcs annotation exists and has
// spec.service.consume=true. The annotation is meaningful only when
// the Service is also marked shared; if shared is not set, presence of
// the ACL annotation is rejected outright so users don't think
// they've configured something that takes effect.
func (v *ServiceCustomValidator) validateAllowedConsumers(ctx context.Context, svc *corev1.Service, sharedRequested bool, annPath *field.Path) (field.ErrorList, error) {
	raw, ok := svc.Annotations[ServiceAnnotationAllowedConsumerVpcs]
	if !ok {
		return nil, nil
	}

	aclPath := annPath.Key(ServiceAnnotationAllowedConsumerVpcs)
	if !sharedRequested {
		return field.ErrorList{field.Invalid(aclPath, raw, "shared-service-allowed-consumer-vpcs has no effect without the shared-service annotation")}, nil
	}

	parts := strings.Split(raw, ",")
	var errs field.ErrorList
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			errs = append(errs, field.Invalid(aclPath, name, "duplicate Vpc in allowed-consumer-vpcs"))
			continue
		}
		seen[name] = struct{}{}

		var consumerVpc juneauv1alpha1.Vpc
		if err := v.Get(ctx, client.ObjectKey{Name: name}, &consumerVpc); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(aclPath, name, "Vpc does not exist"))
				continue
			}
			return nil, err
		}
		if !consumerVpc.Spec.Service.Consumes() {
			errs = append(errs, field.Invalid(aclPath, name, fmt.Sprintf("Vpc %q does not have spec.service.consume=true", name)))
		}
	}
	if len(seen) == 0 {
		errs = append(errs, field.Invalid(aclPath, raw, "must list at least one Vpc when set"))
	}
	return errs, nil
}

// isSharedServiceAnnotation reports whether the annotation value opts the
// Service in to the shared-service path. Only the canonical "true" enables
// it; any other value (including absent) is treated as opt-out so a
// typo cannot accidentally widen the Service's reachability.
func isSharedServiceAnnotation(value string) bool {
	return value == "true"
}

// serviceVpc returns the Vpc that owns the Service. If the annotation is
// absent, the Service is treated as belonging to the default Vpc.
func serviceVpc(svc *corev1.Service) string {
	if v := svc.Annotations[ServiceAnnotationVpc]; v != "" {
		return v
	}
	return defaultServiceVpc
}
