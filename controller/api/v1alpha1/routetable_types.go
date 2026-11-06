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

	// Routes is the table the data plane programs: the routes the
	// controller adds on its own for the Vpc, followed by spec.routes
	// with their references resolved.
	Routes  []ResolvedRoute `json:"routes,omitempty"`
	TableID uint32          `json:"tableID,omitempty"`
}

// Route is one entry of spec.routes.
type Route struct {
	// +kubebuilder:validation:MinLength=1
	Dst string   `json:"dst"`
	Via RouteVia `json:"via"`
}

type RouteVia struct {
	// +kubebuilder:validation:Enum=connected;endpoint;internetGateway;service;natGateway;vpcPeering;transitGateway;vpcEndpoint;blackhole
	Type RouteViaType `json:"type"`
	// Endpoint is required when type=endpoint. It names one NIC of a
	// workload, not one Pod, so the route follows the workload when a
	// new Pod replaces the old one.
	// +optional
	Endpoint *RouteEndpointReference `json:"endpoint,omitempty"`
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

// RouteEndpointReference names one NIC of a workload by the allocation
// identity its Pods share. The controller resolves it to the
// NetworkEndpoint of the NetworkInterface that holds the address of
// that identity right now.
type RouteEndpointReference struct {
	// Namespace is the namespace of the workload's Pods.
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// AllocationIdentity is the NetworkInterface.spec.allocationIdentity
	// of the workload. A Pod sets it with the
	// juneau.loutres.me/allocation-identity annotation.
	// +required
	// +kubebuilder:validation:MinLength=1
	AllocationIdentity string `json:"allocationIdentity"`
	// Interface is the name of the NIC inside the Pod, such as eth0.
	// +required
	// +kubebuilder:validation:MinLength=1
	Interface string `json:"interface"`
}

// ResolvedRoute is one entry of the table the data plane programs.
type ResolvedRoute struct {
	Dst string   `json:"dst"`
	Via RouteVia `json:"via"`
	// Subnet is the Subnet the data plane forwards the packet into: the
	// Subnet of a connected route, the peer Subnet of a vpcPeering
	// route, or the Subnet of the endpoint of an endpoint route.
	// +optional
	Subnet string `json:"subnet,omitempty"`
	// L2Network names the segment a connected route leads to when the
	// destination is an L2Network rather than a Subnet. The data plane
	// hands the packet to the gateway port of that segment, and the
	// segment forwards it from there on its own tables.
	// +optional
	L2Network string `json:"l2Network,omitempty"`
	// TransitGatewayRouteTable names the TransitGatewayRouteTable the
	// data plane consults for this route. The controller resolves it
	// from the attachment's association.
	// +optional
	TransitGatewayRouteTable string `json:"transitGatewayRouteTable,omitempty"`
	// NetworkEndpoint is the NetworkEndpoint via.endpoint resolved to.
	// It is set only on an Active endpoint route.
	// +optional
	NetworkEndpoint *ResolvedNetworkEndpointReference `json:"networkEndpoint,omitempty"`
	// State tells whether the data plane forwards traffic for Dst
	// (Active) or drops it (Blackhole).
	// +required
	// +kubebuilder:validation:Enum=Active;Blackhole
	State RouteState `json:"state"`
	// Message says why the controller drops traffic that spec.routes
	// asked it to forward. It is empty on every other route.
	// +optional
	Message string `json:"message,omitempty"`
}

// ResolvedNetworkEndpointReference names a NetworkEndpoint.
type ResolvedNetworkEndpointReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// RouteState is what the data plane does with traffic for a route.
type RouteState string

const (
	// RouteStateActive means the data plane forwards traffic for the
	// route.
	RouteStateActive RouteState = "Active"
	// RouteStateBlackhole means the data plane drops traffic for the
	// route. That is what a blackhole route asks for, and also what an
	// endpoint route does while its endpoint cannot be resolved.
	RouteStateBlackhole RouteState = "Blackhole"
)

type RouteViaType string

const (
	ViaConnected RouteViaType = "connected"
	// ViaEndpoint sends the matching destination to the NIC of a
	// workload, which forwards it on by itself.
	ViaEndpoint        RouteViaType = "endpoint"
	ViaInternetGateway RouteViaType = "internetGateway"
	ViaService         RouteViaType = "service"
	// ViaNATGateway delegates the matching destination to a
	// NATGateway resource that performs N:1 NAPT towards the
	// associated ExternalNetwork.
	ViaNATGateway RouteViaType = "natGateway"
	// ViaVpcPeering sends the matching destination to a Subnet of the
	// Vpc on the other side of the named VpcPeering. The controller
	// resolves ResolvedRoute.Subnet to that peer Subnet, so the data plane
	// forwards exactly like a connected route.
	ViaVpcPeering RouteViaType = "vpcPeering"
	// ViaTransitGateway hands the matching destination to a
	// TransitGateway. The controller resolves
	// ResolvedRoute.TransitGatewayRouteTable from the association of the
	// attachment that connects this Vpc, and the data plane does a
	// second lookup in that table to find the target Subnet.
	ViaTransitGateway RouteViaType = "transitGateway"
	// ViaVpcEndpoint covers the Vpc's endpoint pool CIDRs. The data plane
	// resolves the destination VIP to the backing Service ClusterIP
	// before running the ordinary Service path, so an address in the pool
	// with no VpcEndpoint behind it is dropped instead of being looked up
	// as a ClusterIP.
	ViaVpcEndpoint RouteViaType = "vpcEndpoint"
	// ViaBlackhole drops the matching destination.
	ViaBlackhole RouteViaType = "blackhole"
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
