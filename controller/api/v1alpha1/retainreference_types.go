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

// RetainReference names an object that keeps an allocation reserved while
// it exists. It is carried from NetworkInterface down to AllocationClaim
// and AllocationLease, and the lease starts its TTL only after the object
// is gone.
//
// The reference is deliberately generic: the controller resolves it as an
// unstructured object, so any kind the cluster serves can hold an
// allocation. A KubeVirt VirtualMachine is the first user, which is how a
// stopped virtual machine keeps its address without its pod.
type RetainReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	APIVersion string `json:"apiVersion"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Kind string `json:"kind"`
	// Namespace of the referenced object. Empty for cluster scoped kinds.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}
