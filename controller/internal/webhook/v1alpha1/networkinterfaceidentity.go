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
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// validateNetworkInterfaceIdentity checks a spec.networkInterface on an
// AllocationClaim or AllocationLease. A nil identity is valid, because only
// the claims of NetworkInterfaces with an allocation identity carry one; an
// identity that is present has to be complete.
func validateNetworkInterfaceIdentity(identity *juneauv1alpha1.NetworkInterfaceIdentity, path *field.Path) field.ErrorList {
	if identity == nil {
		return nil
	}

	var errs field.ErrorList
	if identity.Namespace == "" {
		errs = append(errs, field.Required(path.Child("namespace"), "namespace of the network interface is required"))
	} else {
		for _, msg := range validation.IsDNS1123Label(identity.Namespace) {
			errs = append(errs, field.Invalid(path.Child("namespace"), identity.Namespace, msg))
		}
	}
	if identity.AllocationIdentity == "" {
		errs = append(errs, field.Required(path.Child("allocationIdentity"), "allocation identity of the network interface is required"))
	} else {
		errs = append(errs, juneauv1alpha1.ValidateAllocationIdentity(identity.AllocationIdentity, path.Child("allocationIdentity"))...)
	}
	if identity.Interface == "" {
		errs = append(errs, field.Required(path.Child("interface"), "interface name of the network interface is required"))
	}
	return errs
}

// validateNetworkInterfaceIdentityUpdate keeps spec.networkInterface
// set-once. An object written before the field existed may gain it, but a
// value that is there can be neither changed nor removed.
func validateNetworkInterfaceIdentityUpdate(oldIdentity, newIdentity *juneauv1alpha1.NetworkInterfaceIdentity, path *field.Path) field.ErrorList {
	if oldIdentity == nil || (newIdentity != nil && *oldIdentity == *newIdentity) {
		return nil
	}
	return field.ErrorList{field.Invalid(path, newIdentity, path.String()+" is immutable once set")}
}
