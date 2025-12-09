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

// IPLeaseSpec defines the desired state of IPLease.
type IPLeaseSpec struct {
	PodRef IPLeasePodReference `json:"podRef"`

	Vpc string          `json:"vpc"`
	Subnet string       `json:"subnet"`
	Address string      `json:"address"`

  TTLSeconds *int32 `json:"ttlSeconds,omitempty"`
	OwnerDeletionTimeStamp *metav1.Time `json:"ownerDeletionTimestamp,omitempty"`
}

// IPLeaseStatus defines the observed state of IPLease.
type IPLeaseStatus struct {
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Phase IPLeasePhase `json:"phase,omitempty"`

  PodDisplayName string `json:"podDisplayName,omitempty"`

	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

type IPLeasePodReference struct {
	Namespace string `json:"namespace"`
	Name 		string `json:"name"`
	Interface string `json:"interface"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:resource:shortName={"lease"}
// +kubebuilder:printcolumn:name="Pod",type="string",JSONPath=".status.podDisplayName"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"

// IPLease is the Schema for the ipleases API.
type IPLease struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IPLeaseSpec   `json:"spec,omitempty"`
	Status IPLeaseStatus `json:"status,omitempty"`
}

type IPLeasePhase string

const (
	IPLeaseStatusBound string = "Bound"
	IPLeaseStatusExpired string = "Expired"
	IPLeaseStatusExpiringSoon string = "ExpiringSoon"

	IPLeasePhaseActive	 IPLeasePhase = "Active"
	IPLeasePhaseReleased IPLeasePhase = "Released"
	IPLeasePhaseExpired	 IPLeasePhase = "Expired"
	IPLeasePhaseDeleting IPLeasePhase = "Deleting"
)

// +kubebuilder:object:root=true

// IPLeaseList contains a list of IPLease.
type IPLeaseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPLease `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IPLease{}, &IPLeaseList{})
}
