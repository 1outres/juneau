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

// TransitGatewayRouteTableSpec defines the desired state of
// TransitGatewayRouteTable.
type TransitGatewayRouteTableSpec struct {
	// TransitGateway names the TransitGateway this route table belongs
	// to. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	TransitGateway string `json:"transitGateway"`

	// Routes are static routes. A static route always wins over a
	// propagated route for the same destination.
	// +optional
	Routes []TransitGatewayRoute `json:"routes,omitempty"`
}

// TransitGatewayRoute is one static entry of a TransitGatewayRouteTable.
type TransitGatewayRoute struct {
	// Dst is the destination prefix. It must match the CIDR of a Subnet
	// in the target attachment's Vpc exactly, because the data plane
	// resolves the route to a single destination Subnet VNI.
	// +required
	// +kubebuilder:validation:MinLength=1
	Dst string `json:"dst"`

	// Attachment names the TransitGatewayAttachment that traffic for
	// Dst is sent to. Required unless Blackhole is true.
	// +optional
	Attachment string `json:"attachment,omitempty"`

	// Blackhole drops traffic for Dst instead of forwarding it.
	// +optional
	Blackhole bool `json:"blackhole,omitempty"`
}

// TransitGatewayRouteTableStatus defines the observed state of
// TransitGatewayRouteTable.
type TransitGatewayRouteTableStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// TableID is the cluster-wide identifier the data plane keys its
	// transit-gateway routing layer by.
	TableID uint32 `json:"tableID,omitempty"`

	// Routes is the resolved routing table: propagated routes from
	// every attachment that propagates into this table, overridden by
	// the static spec.routes for the same destination. Sorted by dst.
	Routes []ResolvedTransitGatewayRoute `json:"routes,omitempty"`
}

// ResolvedTransitGatewayRoute is one entry of the resolved routing
// table the data plane programs.
type ResolvedTransitGatewayRoute struct {
	Dst        string `json:"dst"`
	Attachment string `json:"attachment,omitempty"`
	// Subnet is the resolved target Subnet whose VNI and gateway MAC
	// the data plane forwards to. Empty when Blackhole is true.
	Subnet    string `json:"subnet,omitempty"`
	Blackhole bool   `json:"blackhole,omitempty"`
	// Origin records how the route entered the table.
	// +kubebuilder:validation:Enum=static;propagated
	Origin TransitGatewayRouteOrigin `json:"origin"`
}

// TransitGatewayRouteOrigin tells a static route apart from one that an
// attachment propagated into the table.
type TransitGatewayRouteOrigin string

const (
	// TransitGatewayRouteOriginStatic marks a route that comes from
	// spec.routes.
	TransitGatewayRouteOriginStatic TransitGatewayRouteOrigin = "static"
	// TransitGatewayRouteOriginPropagated marks a route that an
	// attachment advertised through spec.propagations.
	TransitGatewayRouteOriginPropagated TransitGatewayRouteOrigin = "propagated"
)

const (
	TransitGatewayRouteTableStatusReady string = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="TransitGateway",type="string",JSONPath=".spec.transitGateway"
// +kubebuilder:printcolumn:name="TableID",type="integer",JSONPath=".status.tableID"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// TransitGatewayRouteTable is the Schema for the
// transitgatewayroutetables API.
type TransitGatewayRouteTable struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TransitGatewayRouteTableSpec   `json:"spec,omitempty"`
	Status TransitGatewayRouteTableStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TransitGatewayRouteTableList contains a list of
// TransitGatewayRouteTable.
type TransitGatewayRouteTableList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransitGatewayRouteTable `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TransitGatewayRouteTable{}, &TransitGatewayRouteTableList{})
}
