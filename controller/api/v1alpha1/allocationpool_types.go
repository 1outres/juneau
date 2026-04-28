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

type AllocationType string

const (
	AllocationTypeNumber AllocationType = "number"
	AllocationTypeIP     AllocationType = "ip"
)

type AllocationStrategy string

const (
	AllocationStrategyFirstFit AllocationStrategy = "firstFit"
)

// AllocationPoolSpec defines the desired state of AllocationPool.
type AllocationPoolSpec struct {
	// +kubebuilder:default=number
	// +kubebuilder:validation:Enum=number;ip
	Type AllocationType `json:"type,omitempty"`

	// +kubebuilder:default=firstFit
	// +kubebuilder:validation:Enum=firstFit
	Strategy AllocationStrategy `json:"strategy,omitempty"`

	Number *AllocationPoolNumberSpec `json:"number,omitempty"`
	IP     *AllocationPoolIPSpec     `json:"ip,omitempty"`
}

type AllocationPoolNumberSpec struct {
	// +kubebuilder:validation:Minimum=1
	Min uint64 `json:"min"`

	// +kubebuilder:validation:Minimum=1
	Max uint64 `json:"max"`
}

type AllocationPoolIPSpec struct {
	// CIDR ranges that participate in this pool. The union forms the
	// candidate address space.
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	CIDRs []string `json:"cidrs"`

	// Excluded lists individual addresses that must never be allocated.
	// Typically populated with reserved IPs such as gateway, network or
	// broadcast addresses.
	// +listType=set
	Excluded []string `json:"excluded,omitempty"`
}

// AllocationPoolStatus defines the observed state of AllocationPool.
type AllocationPoolStatus struct {
	ObservedGeneration  int64              `json:"observedGeneration,omitempty"`
	AllocationVersion   uint64             `json:"allocationVersion,omitempty"`
	LastAllocatedNumber uint64             `json:"lastAllocatedNumber,omitempty"`
	LastAllocatedIP     string             `json:"lastAllocatedIP,omitempty"`
	Conditions          []metav1.Condition `json:"conditions,omitempty"`
}

const (
	AllocationPoolStatusReady = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Type",type="string",JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="Strategy",type="string",JSONPath=".spec.strategy"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// AllocationPool is the Schema for the allocationpools API.
type AllocationPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AllocationPoolSpec   `json:"spec,omitempty"`
	Status AllocationPoolStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AllocationPoolList contains a list of AllocationPool.
type AllocationPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AllocationPool `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AllocationPool{}, &AllocationPoolList{})
}
