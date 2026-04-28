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

// ExternalNetworkAttachmentSpec defines the desired state of
// ExternalNetworkAttachment.
type ExternalNetworkAttachmentSpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	ExternalNetwork string `json:"externalNetwork"`

	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`
}

// ExternalNetworkAttachmentStatus defines the observed state of
// ExternalNetworkAttachment.
type ExternalNetworkAttachmentStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// AssignedIP is the per-(ExternalNetwork, Node) NAPT source IP
	// allocated for this attachment. Populated by the reconciler once
	// the underlying AllocationClaim resolves to an address.
	AssignedIP string `json:"assignedIP,omitempty"`
}

const (
	ExternalNetworkAttachmentStatusReady = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="ExternalNetwork",type="string",JSONPath=".spec.externalNetwork"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="AssignedIP",type="string",JSONPath=".status.assignedIP"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// ExternalNetworkAttachment is the Schema for the externalnetworkattachments API.
type ExternalNetworkAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExternalNetworkAttachmentSpec   `json:"spec,omitempty"`
	Status ExternalNetworkAttachmentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExternalNetworkAttachmentList contains a list of ExternalNetworkAttachment.
type ExternalNetworkAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExternalNetworkAttachment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ExternalNetworkAttachment{}, &ExternalNetworkAttachmentList{})
}
