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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AddressPoolSpec defines the desired state of AddressPool.
type AddressPoolSpec struct {
	// +required
	// +kubebuilder:validation:Enum=bgp;arp
	AdvertiseMode AddressPoolAdvertiseMode `json:"advertiseMode"`

	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MinLength=1
	// +listType=set
	Addresses []string `json:"addresses"`
}

// AddressPoolStatus defines the observed state of AddressPool.
type AddressPoolStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// TotalAddresses is the number of addresses the pool can hand out. It
	// follows the allocator: the network and broadcast addresses of each
	// CIDR are not counted. Capped at the maximum int64 value for very
	// large IPv6 prefixes.
	// +optional
	TotalAddresses int64 `json:"totalAddresses,omitempty"`

	// AllocatedAddresses is the number of those addresses taken by allocated
	// claims and by leases that still hold a value.
	// +optional
	AllocatedAddresses int64 `json:"allocatedAddresses,omitempty"`

	// AvailableAddresses is the number of addresses that can still be handed
	// out.
	// +optional
	AvailableAddresses int64 `json:"availableAddresses,omitempty"`
}

type AddressPoolAdvertiseMode string

const (
	AddressPoolAdvertiseModeBGP AddressPoolAdvertiseMode = "bgp"
	AddressPoolAdvertiseModeARP AddressPoolAdvertiseMode = "arp"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.advertiseMode"
// +kubebuilder:printcolumn:name="Total",type="integer",JSONPath=".status.totalAddresses"
// +kubebuilder:printcolumn:name="Allocated",type="integer",JSONPath=".status.allocatedAddresses"
// +kubebuilder:printcolumn:name="Available",type="integer",JSONPath=".status.availableAddresses"

// AddressPool is the Schema for the addresspools API.
type AddressPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AddressPoolSpec   `json:"spec,omitempty"`
	Status AddressPoolStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AddressPoolList contains a list of AddressPool.
type AddressPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AddressPool `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AddressPool{}, &AddressPoolList{})
}
