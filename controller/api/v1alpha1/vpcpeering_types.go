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

// VpcPeeringSpec defines the desired state of VpcPeering.
//
// A VpcPeering connects two Vpcs so that a RouteTable in either one may
// carry a route with via.type=vpcPeering towards a Subnet of the other.
// The peering itself installs no route: every prefix that should be
// reachable has to be written into a RouteTable explicitly.
//
// Requester and Accepter name the two sides. Juneau has no accept
// workflow — both Vpcs live in the same cluster under one administrator
// — so the two fields only fix a stable order for status messages and
// keep the vocabulary close to AWS VPC peering.
type VpcPeeringSpec struct {
	// Requester is one side of the peering. Immutable.
	// +required
	Requester VpcPeeringEndpoint `json:"requester"`

	// Accepter is the other side of the peering. Immutable.
	// +required
	Accepter VpcPeeringEndpoint `json:"accepter"`
}

// VpcPeeringEndpoint names one side of a peering.
type VpcPeeringEndpoint struct {
	// Vpc names the Vpc on this side of the peering.
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`
}

// VpcPeeringStatus defines the observed state of VpcPeering.
type VpcPeeringStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

const (
	VpcPeeringStatusReady string = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Requester",type="string",JSONPath=".spec.requester.vpc"
// +kubebuilder:printcolumn:name="Accepter",type="string",JSONPath=".spec.accepter.vpc"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// VpcPeering is the Schema for the vpcpeerings API.
type VpcPeering struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VpcPeeringSpec   `json:"spec,omitempty"`
	Status VpcPeeringStatus `json:"status,omitempty"`
}

// Connects reports whether vpcName is one of the two sides of this
// peering.
func (s *VpcPeeringSpec) Connects(vpcName string) bool {
	return s.Requester.Vpc == vpcName || s.Accepter.Vpc == vpcName
}

// PeerOf returns the Vpc on the other side of vpcName. The second
// return value is false when vpcName is not part of this peering.
func (s *VpcPeeringSpec) PeerOf(vpcName string) (string, bool) {
	switch vpcName {
	case s.Requester.Vpc:
		return s.Accepter.Vpc, true
	case s.Accepter.Vpc:
		return s.Requester.Vpc, true
	default:
		return "", false
	}
}

// +kubebuilder:object:root=true

// VpcPeeringList contains a list of VpcPeering.
type VpcPeeringList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VpcPeering `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VpcPeering{}, &VpcPeeringList{})
}
