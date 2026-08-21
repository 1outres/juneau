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

package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// externalNetworkAdvertiseMode returns the advertise mode the AddressPools
// behind an ExternalNetwork of this type must declare. An unknown type is an
// error rather than a default: picking a mode for it would hand the address to
// a data plane that never answers for it.
func externalNetworkAdvertiseMode(networkType juneauv1alpha1.ExternalNetworkType) (juneauv1alpha1.AddressPoolAdvertiseMode, error) {
	switch networkType {
	case juneauv1alpha1.ExternalNetworkTypeBGP:
		return juneauv1alpha1.AddressPoolAdvertiseModeBGP, nil
	case juneauv1alpha1.ExternalNetworkTypeARP:
		return juneauv1alpha1.AddressPoolAdvertiseModeARP, nil
	default:
		return "", fmt.Errorf("unsupported ExternalNetwork type %q", networkType)
	}
}

// supportsExternalNetworkType reports whether juneau can advertise addresses
// for an ExternalNetwork of this type.
func supportsExternalNetworkType(networkType juneauv1alpha1.ExternalNetworkType) bool {
	_, err := externalNetworkAdvertiseMode(networkType)
	return err == nil
}

// arpAdvertisementSpec is the ARPAdvertisement a consumer wants to exist.
type arpAdvertisementSpec struct {
	Name            string
	ExternalNetwork string
	Address         string
	NodeName        string
}

func (s arpAdvertisementSpec) validate() error {
	fields := []struct {
		name  string
		value string
	}{
		{"name", s.Name},
		{"externalNetwork", s.ExternalNetwork},
		{"address", s.Address},
		{"nodeName", s.NodeName},
	}
	for _, field := range fields {
		if field.value == "" {
			return fmt.Errorf("ARPAdvertisement %s is empty", field.name)
		}
	}
	return nil
}

// arpAdvertisementOwnership decides who removes the ARPAdvertisement once its
// consumer stops wanting it. A namespaced consumer cannot use
// arpAdvertisementOwnedBy because Kubernetes rejects an OwnerReference from a
// namespaced object to a cluster-scoped one; it supplies an implementation
// that adds no reference and deletes the advertisement from its finalizer.
type arpAdvertisementOwnership interface {
	applyTo(advertisement *juneauv1alpha1.ARPAdvertisement) error
}

// arpAdvertisementOwnedBy hands the ARPAdvertisement to Kubernetes garbage
// collection through an OwnerReference. Only a cluster-scoped consumer can use
// it.
type arpAdvertisementOwnedBy struct {
	Owner  client.Object
	Scheme *runtime.Scheme
}

func (o arpAdvertisementOwnedBy) applyTo(advertisement *juneauv1alpha1.ARPAdvertisement) error {
	return controllerutil.SetControllerReference(o.Owner, advertisement, o.Scheme)
}

// ensureARPAdvertisement makes the ARPAdvertisement named by desired match
// desired. spec.nodeName is rewritten in place rather than recreated under a
// new name: the webhook keeps spec.address immutable and refuses a second
// advertisement of the same address, so a create-then-delete move would be
// rejected while the old object still holds the address.
func ensureARPAdvertisement(ctx context.Context, c client.Client, desired arpAdvertisementSpec, ownership arpAdvertisementOwnership) error {
	if err := desired.validate(); err != nil {
		return err
	}

	advertisement := &juneauv1alpha1.ARPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: desired.Name},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, c, advertisement, func() error {
		advertisement.Spec.ExternalNetwork = desired.ExternalNetwork
		advertisement.Spec.Address = desired.Address
		advertisement.Spec.NodeName = desired.NodeName
		return ownership.applyTo(advertisement)
	})
	if err != nil {
		return fmt.Errorf("ensure ARPAdvertisement %q: %w", desired.Name, err)
	}
	return nil
}

// deleteARPAdvertisement removes the ARPAdvertisement a consumer no longer
// wants. ARPAdvertisement carries no finalizer, so the address is free for
// another node as soon as the delete lands.
func deleteARPAdvertisement(ctx context.Context, c client.Client, name string) error {
	return deleteAdvertisement(ctx, c, &juneauv1alpha1.ARPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
}

func deleteBGPAdvertisement(ctx context.Context, c client.Client, name string) error {
	return deleteAdvertisement(ctx, c, &juneauv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
}

func deleteAdvertisement(ctx context.Context, c client.Client, advertisement client.Object) error {
	if err := c.Delete(ctx, advertisement); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("delete advertisement %q: %w", advertisement.GetName(), err)
	}
	return nil
}
