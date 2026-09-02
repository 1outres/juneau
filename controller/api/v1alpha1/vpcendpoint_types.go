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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type VpcEndpointServiceReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// VpcEndpointSpec defines a Vpc-local frontend for a Kubernetes Service.
type VpcEndpointSpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`
	// +required
	Service VpcEndpointServiceReference `json:"service"`

	// DNSNames lists fully-qualified names that resolve to the endpoint address
	// for callers in this Vpc.
	// +optional
	// +listType=set
	DNSNames []string `json:"dnsNames,omitempty"`
}

type VpcEndpointStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	Address            string             `json:"address,omitempty"`
	AllocationClaim    string             `json:"allocationClaim,omitempty"`
}

const (
	VpcEndpointConditionAddressAllocated = "AddressAllocated"
	VpcEndpointConditionServiceAccepted  = "ServiceAccepted"
	VpcEndpointConditionReady            = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Vpc",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="Address",type="string",JSONPath=".status.address"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
type VpcEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VpcEndpointSpec   `json:"spec,omitempty"`
	Status            VpcEndpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type VpcEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VpcEndpoint `json:"items"`
}

func init() { SchemeBuilder.Register(&VpcEndpoint{}, &VpcEndpointList{}) }
