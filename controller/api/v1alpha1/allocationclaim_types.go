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
	// PoolRefs lists candidate pools, evaluated in order. The first pool
	// that has a free value satisfying the claim wins.
	// +required
	// +kubebuilder:validation:MinItems=1
	PoolRefs []AllocationPoolReference `json:"poolRefs"`

	// +required
	ResourceRef AllocationResourceReference `json:"resourceRef"`

	// Attribute identifies the target field on the owning resource, for example
	// status.vni or status.tableID.
	// +required
	// +kubebuilder:validation:MinLength=1
	Attribute string `json:"attribute"`

	// RequestedNumber pins a specific value for number-typed pools.
	// +kubebuilder:validation:Minimum=1
	RequestedNumber *uint64 `json:"requestedNumber,omitempty"`

	// RequestedIP pins a specific value for ip-typed pools. Must be a valid
	// IPv4/IPv6 string and must fall inside one of the candidate pools'
	// CIDRs (further restricted by AllocationFilter when set).
	RequestedIP *string `json:"requestedIP,omitempty"`

	// AllocationFilter restricts the candidate space inside the pools. Used
	// when a consumer wants to take from a specific subset of CIDRs.
	AllocationFilter *AllocationFilter `json:"allocationFilter,omitempty"`

	// ReleaseAfter specifies how long the AllocationLease should outlive
	// this claim. While the lease is alive, no other claim can take the
	// same value, and a re-created claim with the same identity will
	// inherit the same value. When unset, the lease is deleted immediately
	// alongside the claim.
	ReleaseAfter *metav1.Duration `json:"releaseAfter,omitempty"`
}

type AllocationFilter struct {
	// CIDRs further narrow the candidate address space inside ip-typed
	// pools. Each entry must be a subset of one of the pool CIDRs.
	// +listType=set
	CIDRs []string `json:"cidrs,omitempty"`
}

type AllocationPoolReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type AllocationResourceReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	APIVersion string `json:"apiVersion"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Kind string `json:"kind"`
	// Namespace of the referenced resource. Required when the owner is a
	// namespaced resource; omit for cluster-scoped owners.
	Namespace string `json:"namespace,omitempty"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type AllocationClaimPhase string

const (
	AllocationClaimPhasePending   AllocationClaimPhase = "Pending"
	AllocationClaimPhaseAllocated AllocationClaimPhase = "Allocated"
)

type AllocationValue struct {
	Number uint64 `json:"number,omitempty"`
	IP     string `json:"ip,omitempty"`
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
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Number",type="integer",JSONPath=".status.value.number"
// +kubebuilder:printcolumn:name="IP",type="string",JSONPath=".status.value.ip"
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
