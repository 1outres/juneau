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

// TransitGatewaySpec defines the desired state of TransitGateway.
//
// The gateway is the administrative grouping for its route tables and
// its attachments. Nothing on the gateway itself is configurable: the
// routing behaviour comes from the TransitGatewayRouteTables that belong
// to it and from the TransitGatewayAttachments that connect Vpcs to it.
//
// The gateway is not given a numeric ID. The data plane keys its second
// lookup by TransitGatewayRouteTable.status.tableID, so a gateway ID
// would have no consumer.
type TransitGatewaySpec struct {
}

// TransitGatewayStatus defines the observed state of TransitGateway.
type TransitGatewayStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// DefaultRouteTable names the TransitGatewayRouteTable the
	// reconciler creates and owns for this gateway. Mirrors
	// Vpc.status.mainRouteTable.
	DefaultRouteTable string `json:"defaultRouteTable,omitempty"`
}

const (
	TransitGatewayStatusReady string = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="DefaultRouteTable",type="string",JSONPath=".status.defaultRouteTable"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// TransitGateway is the Schema for the transitgateways API.
type TransitGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TransitGatewaySpec   `json:"spec,omitempty"`
	Status TransitGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TransitGatewayList contains a list of TransitGateway.
type TransitGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransitGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TransitGateway{}, &TransitGatewayList{})
}
