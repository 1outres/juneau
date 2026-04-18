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

// RouteTableSpec defines the desired state of RouteTable.
type RouteTableSpec struct {
	Vpc    string  `json:"vpc"`
	Routes []Route `json:"routes,omitempty"`
}

// RouteTableStatus defines the observed state of RouteTable.
type RouteTableStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	Routes  []Route `json:"routes,omitempty"`
	TableID uint32  `json:"tableID,omitempty"`
}

type Route struct {
	Dst    string   `json:"dst"`
	Via    RouteVia `json:"via"`
	Subnet string   `json:"subnet,omitempty"`
}

type RouteVia struct {
	Type     RouteViaType `json:"type"`
	Endpoint string       `json:"endpointName,omitempty"`
}

type RouteViaType string

const (
	ViaConnnected      RouteViaType = "connected"
	ViaEndpoint        RouteViaType = "endpoint"
	ViaInternetGateway RouteViaType = "internetGateway"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// RouteTable is the Schema for the routetables API.
type RouteTable struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RouteTableSpec   `json:"spec,omitempty"`
	Status RouteTableStatus `json:"status,omitempty"`
}

const (
	RouteTableStatusReady string = "Ready"
)

// +kubebuilder:object:root=true

// RouteTableList contains a list of RouteTable.
type RouteTableList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RouteTable `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RouteTable{}, &RouteTableList{})
}
