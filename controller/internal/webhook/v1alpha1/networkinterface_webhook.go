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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/podnetwork"
)

// nolint:unused
// log is for logging in this package.
var networkinterfacelog = logf.Log.WithName("networkinterface-resource")

// SetupNetworkInterfaceWebhookWithManager registers the webhook for NetworkInterface in the manager.
func SetupNetworkInterfaceWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.NetworkInterface{}).
		WithValidator(&NetworkInterfaceCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&NetworkInterfaceCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-networkinterface,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkinterfaces,verbs=create;update,versions=v1alpha1,name=mnetworkinterface-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkInterfaceCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind NetworkInterface when those are created or updated.
type NetworkInterfaceCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &NetworkInterfaceCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind NetworkInterface.
func (d *NetworkInterfaceCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	networkinterface, ok := obj.(*juneauv1alpha1.NetworkInterface)

	if !ok {
		return fmt.Errorf("expected an NetworkInterface object but got %T", obj)
	}
	networkinterfacelog.Info("Defaulting for NetworkInterface", "name", networkinterface.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-networkinterface,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkinterfaces,verbs=create;update,versions=v1alpha1,name=vnetworkinterface-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkInterfaceCustomValidator struct is responsible for validating the NetworkInterface resource
// when it is created, updated, or deleted.
type NetworkInterfaceCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &NetworkInterfaceCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NetworkInterface.
func (v *NetworkInterfaceCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	networkinterface, ok := obj.(*juneauv1alpha1.NetworkInterface)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterface object but got %T", obj)
	}
	networkinterfacelog.Info("Validation for NetworkInterface upon creation", "name", networkinterface.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")

	network, networkErrs, err := validateNetworkInterfaceNetwork(ctx, v.Reader, networkinterface)
	if err != nil {
		return nil, err
	}
	errs = append(errs, networkErrs...)

	addressErrs := validateNetworkInterfaceAddress(networkinterface.Spec.Address, network, specPath.Child("address"))
	errs = append(errs, addressErrs...)

	sgErrs, sgErr := validateNetworkInterfaceSecurityGroups(ctx, v.Reader, networkinterface, network, specPath.Child("securityGroups"))
	if sgErr != nil {
		return nil, sgErr
	}
	errs = append(errs, sgErrs...)

	errs = append(errs, validateNetworkInterfaceAllocationIdentity(networkinterface.Spec.AllocationIdentity, specPath.Child("allocationIdentity"))...)
	errs = append(errs, validateRetainReference(networkinterface.Spec.RetainWhile, specPath.Child("retainWhile"))...)

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkInterface"}, networkinterface.Name, errs)
		networkinterfacelog.Info("Validation failed for NetworkInterface", "name", networkinterface.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NetworkInterface.
func (v *NetworkInterfaceCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	networkinterface, ok := newObj.(*juneauv1alpha1.NetworkInterface)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterface object for the newObj but got %T", newObj)
	}
	oldNetworkInterface, ok := oldObj.(*juneauv1alpha1.NetworkInterface)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterface object for the oldObj but got %T", oldObj)
	}
	networkinterfacelog.Info("Validation for NetworkInterface upon update", "name", networkinterface.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	podRefPath := specPath.Child("podRef")

	if networkinterface.Spec.NodeName != oldNetworkInterface.Spec.NodeName {
		errs = append(errs, field.Invalid(specPath.Child("nodeName"), networkinterface.Spec.NodeName, "spec.nodeName is immutable"))
	}
	if networkinterface.Spec.Subnet != oldNetworkInterface.Spec.Subnet {
		errs = append(errs, field.Invalid(specPath.Child("subnet"), networkinterface.Spec.Subnet, "spec.subnet is immutable"))
	}
	if networkinterface.Spec.L2Network != oldNetworkInterface.Spec.L2Network {
		errs = append(errs, field.Invalid(specPath.Child("l2Network"), networkinterface.Spec.L2Network, "spec.l2Network is immutable"))
	}
	if networkinterface.Spec.Address != oldNetworkInterface.Spec.Address {
		errs = append(errs, field.Invalid(specPath.Child("address"), networkinterface.Spec.Address, "spec.address is immutable"))
	}
	if networkinterface.Spec.PodRef.UID != oldNetworkInterface.Spec.PodRef.UID {
		errs = append(errs, field.Invalid(podRefPath.Child("uid"), networkinterface.Spec.PodRef.UID, "spec.podRef.uid is immutable"))
	}
	if networkinterface.Spec.PodRef.Name != oldNetworkInterface.Spec.PodRef.Name {
		errs = append(errs, field.Invalid(podRefPath.Child("name"), networkinterface.Spec.PodRef.Name, "spec.podRef.name is immutable"))
	}
	if networkinterface.Spec.PodRef.Interface != oldNetworkInterface.Spec.PodRef.Interface {
		errs = append(errs, field.Invalid(podRefPath.Child("interface"), networkinterface.Spec.PodRef.Interface, "spec.podRef.interface is immutable"))
	}
	if networkinterface.Spec.AllocationIdentity != oldNetworkInterface.Spec.AllocationIdentity {
		errs = append(errs, field.Invalid(specPath.Child("allocationIdentity"), networkinterface.Spec.AllocationIdentity, "spec.allocationIdentity is immutable"))
	}
	if !retainReferenceEqual(networkinterface.Spec.RetainWhile, oldNetworkInterface.Spec.RetainWhile) {
		errs = append(errs, field.Invalid(specPath.Child("retainWhile"), networkinterface.Spec.RetainWhile, "spec.retainWhile is immutable"))
	}

	// Re-validate SG references on update so changing SGs goes through
	// the same vetting as create (existence + same Vpc as the network).
	//
	// Whether the network still exists intentionally is NOT re-checked
	// on update. spec.subnet and spec.l2Network are immutable (enforced
	// above), so any drift since admission means the network was deleted
	// out from under the NetworkInterface — and the controller still
	// needs to take its finalizer-removal update through to release
	// allocations. A validating-webhook reject here would deadlock that
	// path.
	//
	// We do still need the network to check that SGs share its Vpc, so
	// try to read it (best-effort: NotFound is OK).
	if shouldCheckReferences(networkinterface) {
		network, err := podnetwork.ResolveOptional(ctx, v.Reader, podnetwork.InterfaceReference(networkinterface.Spec))
		if err != nil {
			return nil, err
		}

		sgErrs, sgErr := validateNetworkInterfaceSecurityGroups(ctx, v.Reader, networkinterface, network, specPath.Child("securityGroups"))
		if sgErr != nil {
			return nil, sgErr
		}
		errs = append(errs, sgErrs...)
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkInterface"}, networkinterface.Name, errs)
		networkinterfacelog.Info("Validation failed for NetworkInterface", "name", networkinterface.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NetworkInterface.
func (v *NetworkInterfaceCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	networkinterface, ok := obj.(*juneauv1alpha1.NetworkInterface)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterface object but got %T", obj)
	}
	networkinterfacelog.Info("Validation for NetworkInterface upon deletion", "name", networkinterface.GetName())

	return nil, nil
}

// validateNetworkInterfaceNetwork resolves the network the interface
// joins, whichever kind names it, and reports a reference that points at
// nothing. The resolved network comes back so the caller can check the
// address and the SecurityGroups against it.
func validateNetworkInterfaceNetwork(ctx context.Context, c client.Reader, networkinterface *juneauv1alpha1.NetworkInterface) (*podnetwork.Network, field.ErrorList, error) {
	ref := podnetwork.InterfaceReference(networkinterface.Spec)
	if err := ref.Validate(); err != nil {
		return nil, nil, nil
	}

	network, err := podnetwork.Resolve(ctx, c, ref)
	if err != nil {
		if errors.IsNotFound(err) {
			path := field.NewPath("spec").Child("subnet")
			if ref.Kind() == podnetwork.KindL2Network {
				path = field.NewPath("spec").Child("l2Network")
			}
			return nil, field.ErrorList{field.Invalid(path, ref.Name(), fmt.Sprintf("referenced %s does not exist", ref.Kind()))}, nil
		}
		return nil, nil, err
	}

	return network, nil, nil
}

// validateNetworkInterfaceAddress checks a pinned address against the
// network it has to sit in. A network that hands out no address cannot
// honour a pin at all, so asking for one is rejected instead of being
// quietly ignored.
func validateNetworkInterfaceAddress(address string, network *podnetwork.Network, path *field.Path) field.ErrorList {
	if address == "" {
		return nil
	}

	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return field.ErrorList{field.Invalid(path, address, "must be a valid IPv4 address")}
	}

	if network == nil {
		return nil
	}

	if !network.AllocatesAddresses() {
		return field.ErrorList{field.Invalid(path, address,
			fmt.Sprintf("%s hands out no address; it has no spec.cidr", network.Reference))}
	}

	_, cidr, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		return nil
	}

	if !cidr.Contains(ip) {
		return field.ErrorList{field.Invalid(path, address, fmt.Sprintf("must be within %s CIDR %q", network.Reference, network.CIDR))}
	}

	return nil
}

func validateNetworkInterfaceAllocationIdentity(identity string, path *field.Path) field.ErrorList {
	if identity == "" {
		return nil
	}

	var errs field.ErrorList
	// The identity becomes part of the backing AllocationLease object name.
	for _, msg := range validation.IsDNS1123Subdomain(identity) {
		errs = append(errs, field.Invalid(path, identity, msg))
	}
	return errs
}

// validateSecurityGroupsNeedAGateway rejects a SecurityGroup on a NIC
// of an L2Network that has no gateway.
//
// A SecurityGroup is read where a packet crosses a program that
// evaluates policy, and on a segment that is only ever the gateway
// port. Without one nothing on the segment is ever judged, so the
// rules would look configured and filter nothing. This is the same
// rule spec.networkACL follows on the segment itself.
func validateSecurityGroupsNeedAGateway(network *podnetwork.Network, path *field.Path) field.ErrorList {
	if network == nil || network.Reference.Kind() != podnetwork.KindL2Network || network.HasGateway {
		return nil
	}
	return field.ErrorList{field.Forbidden(path,
		fmt.Sprintf("a SecurityGroup on a NIC of %s only applies to traffic crossing the gateway; give the segment a spec.gateway or drop the reference", network.Reference))}
}

// validateNetworkInterfaceSecurityGroups checks that every entry in
// spec.securityGroups names a SecurityGroup that (a) exists, (b)
// belongs to the same Vpc as the network the NetworkInterface joins,
// and (c) is not duplicated within the list.
//
// The first return is the list of field errors; the second is a
// transport-level error (e.g. unrelated apiserver failure) that should
// abort admission.
func validateNetworkInterfaceSecurityGroups(ctx context.Context, c client.Reader, iface *juneauv1alpha1.NetworkInterface, network *podnetwork.Network, path *field.Path) (field.ErrorList, error) {
	if len(iface.Spec.SecurityGroups) == 0 {
		return nil, nil
	}

	var errs field.ErrorList

	if errs := validateSecurityGroupsNeedAGateway(network, path); len(errs) > 0 {
		return errs, nil
	}

	seen := make(map[string]int, len(iface.Spec.SecurityGroups))
	for i, name := range iface.Spec.SecurityGroups {
		if name == "" {
			errs = append(errs, field.Invalid(path.Index(i), name, "must not be empty"))
			continue
		}
		if prev, dup := seen[name]; dup {
			errs = append(errs, field.Duplicate(path.Index(i), fmt.Sprintf("duplicates entry [%d]", prev)))
			continue
		}
		seen[name] = i
	}

	// The network was either resolved (caller passes it in) or
	// unresolved (we surfaced the error already). Without one we cannot
	// enforce the same-Vpc invariant; let the rest of validation flow
	// through.
	expectedVpc := ""
	if network != nil {
		expectedVpc = network.Vpc
	}

	for i, name := range iface.Spec.SecurityGroups {
		if name == "" {
			continue
		}
		var sg juneauv1alpha1.SecurityGroup
		if err := c.Get(ctx, client.ObjectKey{Name: name}, &sg); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(path.Index(i), name, "referenced SecurityGroup does not exist"))
				continue
			}
			return nil, err
		}
		if expectedVpc != "" && sg.Spec.Vpc != expectedVpc {
			errs = append(errs, field.Invalid(path.Index(i), name,
				fmt.Sprintf("SecurityGroup belongs to Vpc %q (expected %q to match the network)", sg.Spec.Vpc, expectedVpc)))
		}
	}

	return errs, nil
}
