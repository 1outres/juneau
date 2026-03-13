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

// ElasticIPAttachmentSpec defines the desired state of ElasticIPAttachment.
type ElasticIPAttachmentSpec struct {
	ElasticIPRef ElasticIPAttachmentElasticIPRef `json:"elasticIPRef"`
	TargetRef    ElasticIPAttachmentTargetRef    `json:"targetRef"`
}

type ElasticIPAttachmentElasticIPRef struct {
	Name string `json:"name"`
}

type ElasticIPAttachmentTargetRef struct {
	NetworkInterfaceName string `json:"networkInterfaceName"`
}

type ElasticIPAttachmentPhase string

const (
	ElasticIPAttachmentPhasePending  ElasticIPAttachmentPhase = "Pending"
	ElasticIPAttachmentPhaseAttached ElasticIPAttachmentPhase = "Attached"
	ElasticIPAttachmentPhaseError    ElasticIPAttachmentPhase = "Error"
)

// ElasticIPAttachmentStatus defines the observed state of ElasticIPAttachment.
type ElasticIPAttachmentStatus struct {
	ObservedGeneration int64                    `json:"observedGeneration,omitempty"`
	Phase              ElasticIPAttachmentPhase `json:"phase,omitempty"`
	Conditions         []metav1.Condition       `json:"conditions,omitempty"`

	ElasticIP string `json:"elasticIP,omitempty"`
	PodIP     string `json:"podIP,omitempty"`
	NodeName  string `json:"nodeName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ElasticIPAttachment is the Schema for the elasticipattachments API.
type ElasticIPAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ElasticIPAttachmentSpec   `json:"spec,omitempty"`
	Status ElasticIPAttachmentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ElasticIPAttachmentList contains a list of ElasticIPAttachment.
type ElasticIPAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ElasticIPAttachment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ElasticIPAttachment{}, &ElasticIPAttachmentList{})
}
