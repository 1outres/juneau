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
	// +required
	// +kubebuilder:validation:MinLength=1
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
	// +kubebuilder:validation:MinLength=1
	Dst    string   `json:"dst"`
	Via    RouteVia `json:"via"`
	Subnet string   `json:"subnet,omitempty"`
	// L2Network names the segment a connected route leads to when the
	// destination is an L2Network rather than a Subnet. The controller
	// resolves it, so it is only ever set in status. The data plane
	// hands the packet to the gateway port of that segment, and the
	// segment forwards it from there on its own tables.
	// +optional
	L2Network string `json:"l2Network,omitempty"`
	// TransitGatewayRouteTable names the TransitGatewayRouteTable the
	// data plane consults for this route. The controller resolves it
	// from the attachment's association, so it is only ever set in
	// status.
	TransitGatewayRouteTable string `json:"transitGatewayRouteTable,omitempty"`
}

type RouteVia struct {
	// +kubebuilder:validation:Enum=connected;endpoint;internetGateway;service;natGateway;vpcPeering;transitGateway;vpcEndpoint
	Type RouteViaType `json:"type"`
	// Endpoint is required when type=endpoint. Refers to a
	// NetworkEndpoint by name.
	Endpoint string `json:"endpointName,omitempty"`
	// NATGateway is required when type=natGateway. Refers to a
	// NATGateway by name (cluster-scoped).
	NATGateway string `json:"natGateway,omitempty"`
	// VpcPeering is required when type=vpcPeering. Refers to a
	// VpcPeering by name (cluster-scoped).
	VpcPeering string `json:"vpcPeering,omitempty"`
	// TransitGateway is required when type=transitGateway. Refers to a
	// TransitGateway by name (cluster-scoped).
	TransitGateway string `json:"transitGateway,omitempty"`
}

type RouteViaType string

const (
	ViaConnected       RouteViaType = "connected"
	ViaEndpoint        RouteViaType = "endpoint"
	ViaInternetGateway RouteViaType = "internetGateway"
	ViaService         RouteViaType = "service"
	// ViaNATGateway delegates the matching destination to a
	// NATGateway resource that performs N:1 NAPT towards the
	// associated ExternalNetwork.
	ViaNATGateway RouteViaType = "natGateway"
	// ViaVpcPeering sends the matching destination to a Subnet of the
	// Vpc on the other side of the named VpcPeering. The controller
	// resolves Route.Subnet to that peer Subnet, so the data plane
	// forwards exactly like a connected route.
	ViaVpcPeering RouteViaType = "vpcPeering"
	// ViaTransitGateway hands the matching destination to a
	// TransitGateway. The controller resolves
	// Route.TransitGatewayRouteTable from the association of the
	// attachment that connects this Vpc, and the data plane does a
	// second lookup in that table to find the target Subnet.
	ViaTransitGateway RouteViaType = "transitGateway"
	// ViaVpcEndpoint covers the Vpc's endpoint pool CIDRs. The data plane
	// resolves the destination VIP to the backing Service ClusterIP
	// before running the ordinary Service path, so an address in the pool
	// with no VpcEndpoint behind it is dropped instead of being looked up
	// as a ClusterIP.
	ViaVpcEndpoint RouteViaType = "vpcEndpoint"
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
