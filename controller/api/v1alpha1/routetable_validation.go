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
)

// ValidateRouteEndpointReference checks that a RouteEndpointReference can
// name a workload NIC at all. Whether that NIC exists is not checked: a
// route may name a workload before its first Pod runs.
func ValidateRouteEndpointReference(ref RouteEndpointReference, path *field.Path) field.ErrorList {
	var errs field.ErrorList

	namespacePath := path.Child("namespace")
	if ref.Namespace == "" {
		errs = append(errs, field.Required(namespacePath, "name the namespace of the workload"))
	} else {
		for _, msg := range validation.IsDNS1123Label(ref.Namespace) {
			errs = append(errs, field.Invalid(namespacePath, ref.Namespace, msg))
		}
	}

	identityPath := path.Child("allocationIdentity")
	if ref.AllocationIdentity == "" {
		errs = append(errs, field.Required(identityPath, "name the allocation identity of the workload"))
	}
	errs = append(errs, ValidateAllocationIdentity(ref.AllocationIdentity, identityPath)...)

	interfacePath := path.Child("interface")
	if ref.Interface == "" {
		errs = append(errs, field.Required(interfacePath, "name the interface inside the Pod, such as eth0"))
	} else {
		errs = append(errs, validatePodInterfaceName(interfacePath, ref.Interface)...)
	}
	return errs
}
