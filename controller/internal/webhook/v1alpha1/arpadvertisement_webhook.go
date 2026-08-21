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
	"net/netip"
	"slices"

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

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/addressrange"
)

// nolint:unused
// log is for logging in this package.
var arpadvertisementlog = logf.Log.WithName("arpadvertisement-resource")

// SetupARPAdvertisementWebhookWithManager registers the webhook for ARPAdvertisement in the manager.
func SetupARPAdvertisementWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.ARPAdvertisement{}).
		WithValidator(&ARPAdvertisementCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-arpadvertisement,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=arpadvertisements,verbs=create;update,versions=v1alpha1,name=varpadvertisement-v1alpha1.kb.io,admissionReviewVersions=v1

// ARPAdvertisementCustomValidator struct is responsible for validating the ARPAdvertisement resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ARPAdvertisementCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &ARPAdvertisementCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type ARPAdvertisement.
func (v *ARPAdvertisementCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	arpadvertisement, ok := obj.(*juneauloutresmev1alpha1.ARPAdvertisement)
	if !ok {
		return nil, fmt.Errorf("expected a ARPAdvertisement object but got %T", obj)
	}
	arpadvertisementlog.Info("Validation for ARPAdvertisement upon creation", "name", arpadvertisement.GetName())

	return v.validate(ctx, arpadvertisement, nil)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type ARPAdvertisement.
func (v *ARPAdvertisementCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	arpadvertisement, ok := newObj.(*juneauloutresmev1alpha1.ARPAdvertisement)
	if !ok {
		return nil, fmt.Errorf("expected a ARPAdvertisement object for the newObj but got %T", newObj)
	}
	oldAdvertisement, ok := oldObj.(*juneauloutresmev1alpha1.ARPAdvertisement)
	if !ok {
		return nil, fmt.Errorf("expected a ARPAdvertisement object for the oldObj but got %T", oldObj)
	}
	arpadvertisementlog.Info("Validation for ARPAdvertisement upon update", "name", arpadvertisement.GetName())

	return v.validate(ctx, arpadvertisement, oldAdvertisement)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type ARPAdvertisement.
func (v *ARPAdvertisementCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	arpadvertisement, ok := obj.(*juneauloutresmev1alpha1.ARPAdvertisement)
	if !ok {
		return nil, fmt.Errorf("expected a ARPAdvertisement object but got %T", obj)
	}
	arpadvertisementlog.Info("Validation for ARPAdvertisement upon deletion", "name", arpadvertisement.GetName())
	return nil, nil
}

func (v *ARPAdvertisementCustomValidator) validate(ctx context.Context, obj, oldObj *juneauloutresmev1alpha1.ARPAdvertisement) (admission.Warnings, error) {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if oldObj != nil {
		if obj.Spec.ExternalNetwork != oldObj.Spec.ExternalNetwork {
			errs = append(errs, field.Invalid(specPath.Child("externalNetwork"), obj.Spec.ExternalNetwork, "spec.externalNetwork is immutable"))
		}
		if obj.Spec.Address != oldObj.Spec.Address {
			errs = append(errs, field.Invalid(specPath.Child("address"), obj.Spec.Address, "spec.address is immutable"))
		}
	}

	address, addressErr := parseIPv4Address(obj.Spec.Address)
	if addressErr != nil {
		errs = append(errs, field.Invalid(specPath.Child("address"), obj.Spec.Address, "address must be a valid IPv4 address"))
	}

	checkReferences := shouldCheckReferences(obj)
	if checkReferences {
		if addressErr == nil {
			if err := v.validateExternalNetwork(ctx, obj, address, &errs); err != nil {
				return nil, err
			}
		}
		if err := v.validateNodes(ctx, obj, address, &errs); err != nil {
			return nil, err
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "ARPAdvertisement"}, obj.Name, errs)
		arpadvertisementlog.Info("Validation failed for ARPAdvertisement", "name", obj.GetName(), "error", err)
		return nil, err
	}

	if !checkReferences {
		return nil, nil
	}
	return nil, v.validateAddressIsUnclaimed(ctx, obj, address)
}

func (v *ARPAdvertisementCustomValidator) validateExternalNetwork(ctx context.Context, obj *juneauloutresmev1alpha1.ARPAdvertisement, address netip.Addr, errs *field.ErrorList) error {
	externalNetworkPath := field.NewPath("spec", "externalNetwork")

	var externalNetwork juneauloutresmev1alpha1.ExternalNetwork
	if err := v.Get(ctx, client.ObjectKey{Name: obj.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			*errs = append(*errs, field.Invalid(externalNetworkPath, obj.Spec.ExternalNetwork, "referenced ExternalNetwork does not exist"))
			return nil
		}
		return err
	}
	if externalNetwork.Spec.Type != juneauloutresmev1alpha1.ExternalNetworkTypeARP {
		*errs = append(*errs, field.Invalid(externalNetworkPath, obj.Spec.ExternalNetwork, "referenced ExternalNetwork must have type=arp"))
		return nil
	}

	covered, err := v.externalNetworkCovers(ctx, &externalNetwork, address)
	if err != nil {
		return err
	}
	if !covered {
		*errs = append(*errs, field.Invalid(field.NewPath("spec", "address"), obj.Spec.Address, "address must fall inside one of the referenced ExternalNetwork's AddressPools"))
	}
	return nil
}

// externalNetworkCovers reports whether address belongs to one of the ranges
// the ExternalNetwork's AddressPools declare. A pool that is gone, or that
// names a range the AddressPool webhook would have rejected, becomes an error
// rather than a miss: the answer is then unknown, not "no".
func (v *ARPAdvertisementCustomValidator) externalNetworkCovers(ctx context.Context, externalNetwork *juneauloutresmev1alpha1.ExternalNetwork, address netip.Addr) (bool, error) {
	for _, name := range externalNetwork.Spec.AddressPools {
		var pool juneauloutresmev1alpha1.AddressPool
		if err := v.Get(ctx, client.ObjectKey{Name: name}, &pool); err != nil {
			return false, fmt.Errorf("ExternalNetwork %q references AddressPool %q: %w", externalNetwork.Name, name, err)
		}
		for _, raw := range pool.Spec.Addresses {
			start, end, err := addressrange.ParseIPv4Range(raw)
			if err != nil {
				return false, fmt.Errorf("AddressPool %q has an unusable address %q: %w", name, raw, err)
			}
			if start.Compare(address) <= 0 && end.Compare(address) >= 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// validateNodes checks the answering node against the cluster. Handing out an
// address a node already owns would answer for the node itself and take it off
// the external link.
func (v *ARPAdvertisementCustomValidator) validateNodes(ctx context.Context, obj *juneauloutresmev1alpha1.ARPAdvertisement, address netip.Addr, errs *field.ErrorList) error {
	var nodes corev1.NodeList
	if err := v.List(ctx, &nodes); err != nil {
		return err
	}

	specPath := field.NewPath("spec")
	if !slices.ContainsFunc(nodes.Items, func(node corev1.Node) bool { return node.Name == obj.Spec.NodeName }) {
		*errs = append(*errs, field.Invalid(specPath.Child("nodeName"), obj.Spec.NodeName, "referenced Node does not exist"))
	}
	if owner, ok := nodeOwningAddress(nodes.Items, address); ok {
		*errs = append(*errs, field.Invalid(specPath.Child("address"), obj.Spec.Address, fmt.Sprintf("address is the InternalIP of Node %q", owner)))
	}
	return nil
}

// nodeOwningAddress returns the name of the node whose InternalIP is address.
func nodeOwningAddress(nodes []corev1.Node, address netip.Addr) (string, bool) {
	for i := range nodes {
		for _, nodeAddress := range nodes[i].Status.Addresses {
			if nodeAddress.Type == corev1.NodeInternalIP && addressEquals(nodeAddress.Address, address) {
				return nodes[i].Name, true
			}
		}
	}
	return "", false
}

// validateAddressIsUnclaimed keeps one address on one node. Two nodes
// answering the same ARP request would split the traffic by whichever reply
// the peer caches, so the conflict is refused at admission instead of being
// resolved later.
func (v *ARPAdvertisementCustomValidator) validateAddressIsUnclaimed(ctx context.Context, obj *juneauloutresmev1alpha1.ARPAdvertisement, address netip.Addr) error {
	var advertisements juneauloutresmev1alpha1.ARPAdvertisementList
	if err := v.List(ctx, &advertisements); err != nil {
		return err
	}

	for _, other := range advertisements.Items {
		if other.Name == obj.Name || !other.DeletionTimestamp.IsZero() {
			continue
		}
		if !addressEquals(other.Spec.Address, address) {
			continue
		}
		return errors.NewForbidden(
			schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "arpadvertisements"},
			obj.Name,
			fmt.Errorf("address %q is already advertised by ARPAdvertisement %q", obj.Spec.Address, other.Name),
		)
	}

	return nil
}

// parseIPv4Address accepts the IPv4 form only. The ARP responder rewrites an
// IPv4 ARP reply, so an IPv6 address has nowhere to go.
func parseIPv4Address(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv4 address", raw)
	}
	return addr, nil
}

// addressEquals reports whether raw denotes addr. A raw value that is not an
// address denotes no address at all, so it never matches.
func addressEquals(raw string, addr netip.Addr) bool {
	parsed, err := parseIPv4Address(raw)
	if err != nil {
		return false
	}
	return parsed == addr
}
