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

// VpcSpec defines the desired state of Vpc.
type VpcSpec struct {
}

// VpcStatus defines the observed state of Vpc.
type VpcStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	MainRouteTable string `json:"mainRouteTable,omitempty"`
	VpcID          uint32 `json:"vpcID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// Vpc is the Schema for the vpcs API.
type Vpc struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VpcSpec   `json:"spec,omitempty"`
	Status VpcStatus `json:"status,omitempty"`
}

const (
	VpcStatusReady string = "Ready"
)

// +kubebuilder:object:root=true

// VpcList contains a list of Vpc.
type VpcList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Vpc `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Vpc{}, &VpcList{})
}
