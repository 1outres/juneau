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
//
// One ServiceNATAttachment exists per (Node, provider Vpc) pair: each
// provider Vpc (a Vpc with spec.service.provider.natSourceSubnet set)
// allocates one SNAT source IP per Node so that cross-VPC callers
// reaching shared Services in that Vpc receive replies over the
// provider Vpc's fabric back to the originating Node.
type ServiceNATAttachmentSpec struct {
	// NodeName is the Kubernetes Node this attachment belongs to.
	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`

	// Vpc is the provider Vpc whose Service NAT pool the attachment
	// allocates from. The Vpc must have
	// spec.service.provider.natSourceSubnet set.
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`
}

// ServiceNATAttachmentStatus defines the observed state of
// ServiceNATAttachment.
type ServiceNATAttachmentStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// AssignedIP is the per-Node SNAT source IP used to forward
	// traffic from cross-VPC callers into shared Services owned by
	// the provider Vpc. Allocated from the provider Vpc's
	// spec.service.provider.natSourceSubnet by the
	// ServiceNATAttachmentReconciler.
	AssignedIP string `json:"assignedIP,omitempty"`

	// AssignedMAC is the synthetic MAC paired with AssignedIP,
	// published through a derived NetworkEndpoint so the provider
	// Vpc's fabric can resolve the SNAT IP via ARP/fdb back to this
	// Node.
	AssignedMAC string `json:"assignedMAC,omitempty"`

	// Subnet records the Subnet the SNAT IP was allocated from. It
	// mirrors the provider Vpc's spec.service.provider.natSourceSubnet
	// at allocation time and is used by downstream reconcilers
	// (NetworkEndpoint, daemon-side ARP/fdb) to install the entry in
	// the right L2 segment.
	Subnet string `json:"subnet,omitempty"`
}

const (
	ServiceNATAttachmentStatusReady = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Vpc",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="AssignedIP",type="string",JSONPath=".status.assignedIP"
// +kubebuilder:printcolumn:name="Subnet",type="string",JSONPath=".status.subnet"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// ServiceNATAttachment is the Schema for the servicenatattachments API.
//
// One ServiceNATAttachment exists per (Node, provider Vpc) pair and
// represents the SNAT source IP that traffic from cross-VPC callers
// takes when reaching shared Services in the provider Vpc. Resources
// are owned by the provider Vpc and fanned out by the VpcReconciler
// for every Vpc that sets spec.service.provider.natSourceSubnet.
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
