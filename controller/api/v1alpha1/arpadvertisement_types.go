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

// ARPAdvertisementSpec defines the desired state of ARPAdvertisement.
type ARPAdvertisementSpec struct {
	// ExternalNetwork names the ARP-mode ExternalNetwork that owns
	// Address.
	// +required
	// +kubebuilder:validation:MinLength=1
	ExternalNetwork string `json:"externalNetwork"`

	// Address is the IPv4 address answered on the external link. It must
	// fall inside one of the AddressPools behind ExternalNetwork.
	// +required
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`

	// NodeName is the single node that answers ARP requests for Address.
	// It is the only mutable field: a consumer rewrites it to move the
	// address to another node.
	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`
}

// ARPAdvertisementStatus defines the observed state of ARPAdvertisement.
type ARPAdvertisementStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="ExternalNetwork",type="string",JSONPath=".spec.externalNetwork"
// +kubebuilder:printcolumn:name="Address",type="string",JSONPath=".spec.address"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"

// ARPAdvertisement is the Schema for the arpadvertisements API.
type ARPAdvertisement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ARPAdvertisementSpec   `json:"spec,omitempty"`
	Status ARPAdvertisementStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ARPAdvertisementList contains a list of ARPAdvertisement.
type ARPAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ARPAdvertisement `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ARPAdvertisement{}, &ARPAdvertisementList{})
}
