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

// AllocationLeaseSpec defines the desired state of AllocationLease.
//
// AllocationLease records a single (pool, value) reservation that survives
// the deletion of its owning AllocationClaim. While a lease exists no other
// claim can take the same value, and a claim re-created with the same
// ReuseKey will inherit the recorded value. Leases are managed entirely by
// the AllocationClaim controller; consumers of the allocation framework
// should never create or modify AllocationLease objects directly.
type AllocationLeaseSpec struct {
	// PoolRef references the AllocationPool that owns this lease via
	// metadata.ownerReferences. The pool name is also kept here for
	// efficient field-indexed lookups.
	// +required
	PoolRef AllocationPoolReference `json:"poolRef"`

	// Value is the reserved address or number.
	// +required
	Value AllocationValue `json:"value"`

	// ReuseKey identifies the upstream owner so that a re-created
	// AllocationClaim with the same identity can recover the value.
	// +required
	ReuseKey AllocationResourceReference `json:"reuseKey"`

	// OwnerDeletionTimestamp records when the owning AllocationClaim was
	// deleted. While unset, the lease is considered Active and will not be
	// reaped. Once set, the lease is treated as Released and the controller
	// will delete it after TTLSeconds elapses.
	OwnerDeletionTimestamp *metav1.Time `json:"ownerDeletionTimestamp,omitempty"`

	// TTLSeconds is the grace period applied after OwnerDeletionTimestamp.
	// Copied from the originating AllocationClaim.spec.releaseAfter.
	// +kubebuilder:validation:Minimum=0
	TTLSeconds *int32 `json:"ttlSeconds,omitempty"`
}

type AllocationLeasePhase string

const (
	AllocationLeasePhaseActive   AllocationLeasePhase = "Active"
	AllocationLeasePhaseReleased AllocationLeasePhase = "Released"
	AllocationLeasePhaseExpired  AllocationLeasePhase = "Expired"
)

const (
	AllocationLeaseStatusReady = "Ready"
)

// AllocationLeaseStatus defines the observed state of AllocationLease.
type AllocationLeaseStatus struct {
	ObservedGeneration int64                `json:"observedGeneration,omitempty"`
	Phase              AllocationLeasePhase `json:"phase,omitempty"`
	ExpiresAt          *metav1.Time         `json:"expiresAt,omitempty"`
	Conditions         []metav1.Condition   `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Pool",type="string",JSONPath=".spec.poolRef.name"
// +kubebuilder:printcolumn:name="Number",type="integer",JSONPath=".spec.value.number"
// +kubebuilder:printcolumn:name="IP",type="string",JSONPath=".spec.value.ip"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="ExpiresAt",type="string",JSONPath=".status.expiresAt"

// AllocationLease is the Schema for the allocationleases API.
type AllocationLease struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AllocationLeaseSpec   `json:"spec,omitempty"`
	Status AllocationLeaseStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AllocationLeaseList contains a list of AllocationLease.
type AllocationLeaseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AllocationLease `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AllocationLease{}, &AllocationLeaseList{})
}
