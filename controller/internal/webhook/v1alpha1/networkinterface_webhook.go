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

	subnet, subnetErrs, err := validateNetworkInterfaceSubnet(ctx, v.Reader, networkinterface, specPath.Child("subnet"))
	if err != nil {
		return nil, err
	}
	errs = append(errs, subnetErrs...)

	addressErrs := validateNetworkInterfaceAddress(networkinterface.Spec.Address, subnet, specPath.Child("address"))
	errs = append(errs, addressErrs...)

	sgErrs, sgErr := validateNetworkInterfaceSecurityGroups(ctx, v.Reader, networkinterface, subnet, specPath.Child("securityGroups"))
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
	// the same vetting as create (existence + same Vpc as Subnet).
	//
	// Subnet existence intentionally is NOT re-checked on update.
	// spec.subnet is immutable (enforced above), so any drift since
	// admission means the Subnet was deleted out from under the
	// NetworkInterface — and the controller still needs to take its
	// finalizer-removal update through to release allocations. A
	// validating-webhook reject here would deadlock that path.
	//
	// We do still need the Subnet object to check that SGs share its
	// Vpc, so try to fetch it (best-effort: NotFound is OK).
	var subnet *juneauv1alpha1.Subnet
	if networkinterface.Spec.Subnet != "" {
		var fetched juneauv1alpha1.Subnet
		if err := v.Get(ctx, client.ObjectKey{Name: networkinterface.Spec.Subnet}, &fetched); err == nil {
			subnet = &fetched
		} else if !errors.IsNotFound(err) {
			return nil, err
		}
	}

	sgErrs, sgErr := validateNetworkInterfaceSecurityGroups(ctx, v.Reader, networkinterface, subnet, specPath.Child("securityGroups"))
	if sgErr != nil {
		return nil, sgErr
	}
	errs = append(errs, sgErrs...)

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

func validateNetworkInterfaceSubnet(ctx context.Context, c client.Reader, networkinterface *juneauv1alpha1.NetworkInterface, path *field.Path) (*juneauv1alpha1.Subnet, field.ErrorList, error) {
	if networkinterface.Spec.Subnet == "" {
		return nil, nil, nil
	}

	var subnet juneauv1alpha1.Subnet
	if err := c.Get(ctx, client.ObjectKey{Name: networkinterface.Spec.Subnet}, &subnet); err != nil {
		if errors.IsNotFound(err) {
			return nil, field.ErrorList{field.Invalid(path, networkinterface.Spec.Subnet, "referenced Subnet does not exist")}, nil
		}
		return nil, nil, err
	}

	return &subnet, nil, nil
}

func validateNetworkInterfaceAddress(address string, subnet *juneauv1alpha1.Subnet, path *field.Path) field.ErrorList {
	if address == "" {
		return nil
	}

	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return field.ErrorList{field.Invalid(path, address, "must be a valid IPv4 address")}
	}

	if subnet == nil {
		return nil
	}

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return nil
	}

	if !cidr.Contains(ip) {
		return field.ErrorList{field.Invalid(path, address, fmt.Sprintf("must be within Subnet CIDR %q", subnet.Spec.CIDR))}
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

// validateNetworkInterfaceSecurityGroups checks that every entry in
// spec.securityGroups names a SecurityGroup that (a) exists, (b)
// belongs to the same Vpc as the NetworkInterface's Subnet, and (c) is
// not duplicated within the list.
//
// The first return is the list of field errors; the second is a
// transport-level error (e.g. unrelated apiserver failure) that should
// abort admission.
func validateNetworkInterfaceSecurityGroups(ctx context.Context, c client.Reader, iface *juneauv1alpha1.NetworkInterface, subnet *juneauv1alpha1.Subnet, path *field.Path) (field.ErrorList, error) {
	if len(iface.Spec.SecurityGroups) == 0 {
		return nil, nil
	}

	var errs field.ErrorList

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

	// Subnet was either resolved (caller passes it in) or unresolved (we
	// surfaced the error already). Without a subnet we cannot enforce
	// the same-Vpc invariant; let the rest of validation flow through.
	expectedVpc := ""
	if subnet != nil {
		expectedVpc = subnet.Spec.Vpc
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
				fmt.Sprintf("SecurityGroup belongs to Vpc %q (expected %q to match Subnet)", sg.Spec.Vpc, expectedVpc)))
		}
	}

	return errs, nil
}
