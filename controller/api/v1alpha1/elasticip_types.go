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

// ElasticIPSpec defines the desired state of ElasticIP.
type ElasticIPSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ExternalNetwork string `json:"externalNetwork"`
}

type ElasticIPPhase string

const (
	ElasticIPPhasePending   ElasticIPPhase = "Pending"
	ElasticIPPhaseAvailable ElasticIPPhase = "Available"
	ElasticIPPhaseAttached  ElasticIPPhase = "Attached"
	ElasticIPPhaseError     ElasticIPPhase = "Error"
)

// ElasticIPStatus defines the observed state of ElasticIP.
type ElasticIPStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Phase              ElasticIPPhase     `json:"phase,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	Address string `json:"address,omitempty"`

	AttachmentName string `json:"attachmentName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ExternalNetwork",type="string",JSONPath=".spec.externalNetwork"
// +kubebuilder:printcolumn:name="Address",type="string",JSONPath=".status.address"
// +kubebuilder:printcolumn:name="Attachment",type="string",JSONPath=".status.attachmentName"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Allocated",type="string",JSONPath=".status.conditions[?(@.type==\"Allocated\")].status"
// +kubebuilder:printcolumn:name="Attached",type="string",JSONPath=".status.conditions[?(@.type==\"Attached\")].status"

// ElasticIP is the Schema for the elasticips API.
type ElasticIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ElasticIPSpec   `json:"spec,omitempty"`
	Status ElasticIPStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ElasticIPList contains a list of ElasticIP.
type ElasticIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ElasticIP `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ElasticIP{}, &ElasticIPList{})
}
