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

// NetworkEndpointSpec defines the desired state of NetworkEndpoint.
type NetworkEndpointSpec struct {
	PodRef NetworkEndpointPodReference `json:"podRef"`

	NodeName string `json:"nodeName"`

	Subnet string `json:"subnet"`

	Address string `json:"address,omitempty"`

	MACAddress     string `json:"macAddress,omitempty"`
	HostMACAddress string `json:"hostMACAddress,omitempty"`
	Ifindex        int    `json:"ifindex,omitempty"`
}

// NetworkEndpointStatus defines the observed state of NetworkEndpoint.
type NetworkEndpointStatus struct {
	NodeIP string `json:"nodeIP,omitempty"`
}

type NetworkEndpointPodReference struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	UID       string `json:"uid"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={"nwep"}

// NetworkEndpoint is the Schema for the networkendpoints API.
type NetworkEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkEndpointSpec   `json:"spec,omitempty"`
	Status NetworkEndpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkEndpointList contains a list of NetworkEndpoint.
type NetworkEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkEndpoint{}, &NetworkEndpointList{})
}
