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

// SubnetSpec defines the desired state of Subnet.
type SubnetSpec struct {
	// +required
	Vpc string `json:"vpc"`
	// +required
	CIDR string `json:"cidr"`

	// +optional
	// +kubebuilder:default=FirstFit
	AllocationStrategy SubnetAllocationStrategy `json:"allocationStrategy"`
}

// SubnetStatus defines the observed state of Subnet.
type SubnetStatus struct {
	Gateway string `json:"gateway,omitempty"`

	Capacity   uint64 `json:"capacity,omitempty"`
	Used       uint64 `json:"used,omitempty"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// +kubebuilder:validation:Enum=FirstFit;Random
type SubnetAllocationStrategy string

const (
	SubnetAllocationStrategyFirstFit SubnetAllocationStrategy = "FirstFit"
	SubnetAllocationStrategyRandom   SubnetAllocationStrategy = "Random"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// Subnet is the Schema for the subnets API.
type Subnet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SubnetSpec   `json:"spec,omitempty"`
	Status SubnetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SubnetList contains a list of Subnet.
type SubnetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Subnet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Subnet{}, &SubnetList{})
}
