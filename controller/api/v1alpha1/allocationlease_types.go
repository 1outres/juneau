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
// the deletion of its owning AllocationClaim. The lease is named after the
// claim's reuse key, so a claim re-created under that key inherits the
// recorded value. Leases are managed entirely by the AllocationClaim
// controller; consumers of the allocation framework should never create or
// modify AllocationLease objects directly.
type AllocationLeaseSpec struct {
	// PoolRef references the AllocationPool that owns this lease via
	// metadata.ownerReferences. The pool name is also kept here for
	// efficient field-indexed lookups.
	// +required
	PoolRef AllocationPoolReference `json:"poolRef"`

	// Value is the reserved address or number.
	// +required
	Value AllocationValue `json:"value"`

	// ClaimRef identifies the AllocationClaim that currently holds this
	// lease. It changes when a released lease is handed over to another
	// claim that shares the same reuse key.
	//
	// Leases stored before this field existed read back with an empty
	// holder. The schema therefore accepts one, while admission rejects
	// it, so the controller can adopt those leases on the next reconcile
	// but can never write a lease without a holder itself.
	// +optional
	ClaimRef AllocationLeaseClaimReference `json:"claimRef,omitempty"`

	// OwnerDeletionTimestamp records when the owning AllocationClaim was
	// deleted. While unset, the lease is considered Active and will not be
	// reaped. Once set, the lease is treated as Released and the controller
	// will delete it after TTLSeconds elapses.
	OwnerDeletionTimestamp *metav1.Time `json:"ownerDeletionTimestamp,omitempty"`

	// TTLSeconds is the grace period applied after the lease is released.
	// Copied from the originating AllocationClaim.spec.releaseAfter.
	// +kubebuilder:validation:Minimum=0
	TTLSeconds *int32 `json:"ttlSeconds,omitempty"`

	// RetainWhile holds the reservation for as long as the referenced
	// object exists. While it is there the lease stays Retained and the
	// TTL does not run; the countdown starts from
	// Status.RetainReleasedAt instead of OwnerDeletionTimestamp. Unlike
	// the rest of the identity fields this one is mutable, because a new
	// claim generation may point the same lease at a different object.
	// +optional
	RetainWhile *RetainReference `json:"retainWhile,omitempty"`

	// DNS is the Vpc-scoped name binding retained with this IP reservation.
	// +optional
	DNS *AllocationDNSBinding `json:"dns,omitempty"`
}

// AllocationLeaseClaimReference names the AllocationClaim that holds a lease.
type AllocationLeaseClaimReference struct {
	// +optional
	Name string `json:"name,omitempty"`
	// +optional
	UID string `json:"uid,omitempty"`
}

type AllocationLeasePhase string

const (
	AllocationLeasePhaseActive AllocationLeasePhase = "Active"
	// AllocationLeasePhaseRetained means the claim is gone but the object
	// named by Spec.RetainWhile is still there, so the TTL has not started.
	AllocationLeasePhaseRetained AllocationLeasePhase = "Retained"
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

	// RetainReleasedAt records when the controller first observed that
	// the object named by Spec.RetainWhile was gone. It is the start of
	// the TTL for a lease that has a retain reference, and it is cleared
	// again when the object comes back.
	// +optional
	RetainReleasedAt *metav1.Time       `json:"retainReleasedAt,omitempty"`
	Conditions       []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Pool",type="string",JSONPath=".spec.poolRef.name"
// +kubebuilder:printcolumn:name="Claim",type="string",JSONPath=".spec.claimRef.name"
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
