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

// ServiceNATAttachmentSpec defines the desired state of
// ServiceNATAttachment.
type ServiceNATAttachmentSpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`
}

// ServiceNATAttachmentStatus defines the observed state of
// ServiceNATAttachment.
type ServiceNATAttachmentStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// AssignedIP is the per-Node SNAT source IP used to forward traffic
	// from non-default Vpcs into shared Services hosted in the default
	// Vpc. Allocated from the default Subnet's IP pool by the
	// ServiceNATAttachmentReconciler.
	AssignedIP string `json:"assignedIP,omitempty"`

	// AssignedMAC is the synthetic MAC paired with AssignedIP, published
	// through a derived NetworkEndpoint so the default Vpc fabric can
	// resolve the SNAT IP via ARP/fdb back to this Node.
	AssignedMAC string `json:"assignedMAC,omitempty"`
}

const (
	ServiceNATAttachmentStatusReady = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="AssignedIP",type="string",JSONPath=".status.assignedIP"
// +kubebuilder:printcolumn:name="AssignedMAC",type="string",JSONPath=".status.assignedMAC"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// ServiceNATAttachment is the Schema for the servicenatattachments API.
//
// One ServiceNATAttachment exists per Node and represents the SNAT
// source IP that traffic from non-default Vpcs (with EnableService
// enabled) takes when reaching shared Services in the default Vpc.
// Resources are owned by the default Vpc and fanned out by the
// VpcReconciler.
type ServiceNATAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceNATAttachmentSpec   `json:"spec,omitempty"`
	Status ServiceNATAttachmentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceNATAttachmentList contains a list of ServiceNATAttachment.
type ServiceNATAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceNATAttachment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ServiceNATAttachment{}, &ServiceNATAttachmentList{})
}
