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

// NATGatewaySpec defines the desired state of NATGateway.
type NATGatewaySpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`

	// +required
	// +kubebuilder:validation:MinLength=1
	ExternalNetwork string `json:"externalNetwork"`
}

// NATGatewayStatus defines the observed state of NATGateway.
type NATGatewayStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// GatewayID is the cluster-wide identifier allocated for this
	// NATGateway. It is referenced by the data plane to look up
	// per-(node, ExternalNetwork) NAPT source IPs.
	GatewayID uint32 `json:"gatewayID,omitempty"`
}

const (
	NATGatewayStatusReady = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="VPC",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="ExternalNetwork",type="string",JSONPath=".spec.externalNetwork"
// +kubebuilder:printcolumn:name="GatewayID",type="integer",JSONPath=".status.gatewayID"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// NATGateway is the Schema for the natgateways API.
type NATGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NATGatewaySpec   `json:"spec,omitempty"`
	Status NATGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NATGatewayList contains a list of NATGateway.
type NATGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NATGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NATGateway{}, &NATGatewayList{})
}
