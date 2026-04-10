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

// ExternalNetworkSpec defines the desired state of ExternalNetwork.
type ExternalNetworkSpec struct {
	Type ExternalNetworkType `json:"type,omitempty"`

	AddressPools []string `json:"addressPools,omitempty"`
}

// ExternalNetworkStatus defines the observed state of ExternalNetwork.
type ExternalNetworkStatus struct {
}

type ExternalNetworkType string

const (
	ExternalNetworkTypeBGP ExternalNetworkType = "bgp"
	ExternalNetworkTypeARP ExternalNetworkType = "arp"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ExternalNetwork is the Schema for the externalnetworks API.
type ExternalNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExternalNetworkSpec   `json:"spec,omitempty"`
	Status ExternalNetworkStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExternalNetworkList contains a list of ExternalNetwork.
type ExternalNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExternalNetwork `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ExternalNetwork{}, &ExternalNetworkList{})
}
