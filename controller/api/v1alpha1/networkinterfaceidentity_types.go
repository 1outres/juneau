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

// NetworkInterfaceIdentity names the NetworkInterface an allocation belongs
// to, by the three values that make up its reuse key: the namespace, the
// allocation identity of the workload and the interface name inside it.
//
// A NetworkInterface carries these values in its own spec, but it is gone
// while the workload is stopped. The AllocationClaim copies this reference
// onto the AllocationLease so that a consumer can still tell whose address
// a Retained or Released lease holds, without parsing the lease name.
type NetworkInterfaceIdentity struct {
	// Namespace of the NetworkInterface.
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// AllocationIdentity is spec.allocationIdentity of the NetworkInterface.
	// +required
	// +kubebuilder:validation:MinLength=1
	AllocationIdentity string `json:"allocationIdentity"`
	// Interface is spec.podRef.interface of the NetworkInterface, such as
	// eth0.
	// +required
	// +kubebuilder:validation:MinLength=1
	Interface string `json:"interface"`
}
