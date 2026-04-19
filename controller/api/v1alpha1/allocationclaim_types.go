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

// AllocationClaimSpec defines the desired state of AllocationClaim.
type AllocationClaimSpec struct {
	PoolRef AllocationPoolReference `json:"poolRef"`

	ResourceRef AllocationResourceReference `json:"resourceRef"`

	// Attribute identifies the target field on the owning resource, for example
	// status.vni or status.tableID.
	Attribute string `json:"attribute"`

	RequestedNumber *uint64 `json:"requestedNumber,omitempty"`
}

type AllocationPoolReference struct {
	Name string `json:"name"`
}

type AllocationResourceReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
}

type AllocationClaimPhase string

const (
	AllocationClaimPhasePending   AllocationClaimPhase = "Pending"
	AllocationClaimPhaseAllocated AllocationClaimPhase = "Allocated"
)

type AllocationValue struct {
	Number uint64 `json:"number,omitempty"`
}

// AllocationClaimStatus defines the observed state of AllocationClaim.
type AllocationClaimStatus struct {
	ObservedGeneration int64                `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition   `json:"conditions,omitempty"`
	Phase              AllocationClaimPhase `json:"phase,omitempty"`
	Value              AllocationValue      `json:"value,omitempty"`
}

const (
	AllocationClaimStatusReady = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Pool",type="string",JSONPath=".spec.poolRef.name"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Number",type="integer",JSONPath=".status.value.number"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// AllocationClaim is the Schema for the allocationclaims API.
type AllocationClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AllocationClaimSpec   `json:"spec,omitempty"`
	Status AllocationClaimStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AllocationClaimList contains a list of AllocationClaim.
type AllocationClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AllocationClaim `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AllocationClaim{}, &AllocationClaimList{})
}
