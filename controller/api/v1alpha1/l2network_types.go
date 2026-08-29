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

// L2NetworkSpec defines the desired state of L2Network.
//
// An L2Network is a plain Ethernet segment. Juneau forwards on the
// destination MAC address alone and lets every EtherType through, so
// workloads can run their own bridge, DHCP server or router on it. The
// more fields you write, the more Juneau does for the segment: with no
// cidr it only carries frames, with a cidr it also hands out addresses,
// and with a gateway it also joins the rest of the Vpc.
type L2NetworkSpec struct {
	// Vpc is the Vpc this segment belongs to. It draws the tenant
	// boundary, exactly as it does for a Subnet. The default Vpc is not
	// allowed: it is shared by the whole cluster.
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`

	// CIDR turns on address management for the segment. Write it and
	// Juneau hands every attached NIC an address out of the prefix;
	// leave it empty and Juneau hands out nothing, which is what a
	// segment with its own DHCP server wants.
	//
	// A NIC without an address cannot be a Pod's primary NIC, because
	// the container runtime refuses a sandbox whose eth0 has no address.
	// Such an L2Network is for extra NICs only.
	//
	// The prefix must be written in its normalized form (host bits
	// cleared) and must be between /16 and /28, the same range a Subnet
	// accepts. Immutable.
	// +optional
	CIDR string `json:"cidr,omitempty"`

	// Gateway gives the segment a way out. Without it the segment is
	// closed: frames only reach the other NICs on the same L2Network.
	// With it Juneau puts a router port on the segment, and traffic
	// through that port follows the Vpc's RouteTable, NATGateway,
	// Service and NetworkACL rules. Requires CIDR.
	// +optional
	Gateway *L2NetworkGateway `json:"gateway,omitempty"`

	// NetworkACL names the NetworkACL applied to this segment. The
	// referenced ACL must belong to the same Vpc.
	//
	// The ACL only applies to traffic that crosses the gateway. Traffic
	// between two NICs on the same L2Network is never checked against
	// it, because the L2 data plane does not read policy at all. For
	// that reason an L2Network without a gateway may not name an ACL:
	// the rules would have nothing to act on.
	// +optional
	NetworkACL string `json:"networkACL,omitempty"`

	// MTU is the MTU Juneau gives every NIC on this segment. Leave it
	// empty to take the cluster-wide default, which the controller sets
	// from its --default-l2-mtu flag (1450: a 1500-byte underlay minus
	// the 50 bytes of VXLAN overhead).
	//
	// Set it yourself when the underlay is bigger or smaller. A non-IP
	// protocol cannot be fragmented, so a wrong MTU here shows up as
	// frames that disappear.
	// +optional
	// +kubebuilder:validation:Minimum=576
	// +kubebuilder:validation:Maximum=9000
	MTU *int32 `json:"mtu,omitempty"`
}

// L2NetworkGateway is the router port an L2Network puts on its segment.
type L2NetworkGateway struct {
	// Address is the address the gateway answers on. It has to sit
	// inside spec.cidr and may be neither the network nor the broadcast
	// address. Leave it empty to take the first address of the prefix
	// (the `.1`).
	// +optional
	Address string `json:"address,omitempty"`

	// RouteTable selects which RouteTable governs traffic that leaves
	// through this gateway. The referenced RouteTable must belong to the
	// same Vpc. Leave it empty to use the Vpc's main RouteTable.
	// +optional
	RouteTable string `json:"routeTable,omitempty"`
}

// L2NetworkStatus defines the observed state of L2Network.
type L2NetworkStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// VNI is the overlay identifier of this segment. It comes from the
	// same pool as Subnet VNIs, because the data plane keys its
	// forwarding tables on the VNI alone and two segments that shared one
	// would mix their frames.
	VNI uint32 `json:"vni,omitempty"`

	// MTU is the MTU Juneau actually gives the NICs on this segment:
	// spec.mtu when it is set, the controller default otherwise.
	MTU int32 `json:"mtu,omitempty"`

	// Gateway is the resolved gateway address: spec.gateway.address when
	// it is set, the first address of spec.cidr otherwise. Empty when
	// the segment has no gateway.
	Gateway string `json:"gateway,omitempty"`

	// GatewayMAC is the locally administered Ethernet address the
	// gateway port answers ARP with. The controller picks it once and
	// keeps it for as long as the gateway exists, so attached workloads
	// never have to relearn it. Empty when the segment has no gateway.
	GatewayMAC string `json:"gatewayMAC,omitempty"`

	// NetworkACL mirrors the resolved spec.networkACL reference in the
	// same shape a Subnet publishes it, because the daemon programs the
	// gateway port of a segment out of the same subnet_map the Subnet
	// data plane reads. Empty (nil) when spec.networkACL is unset.
	// +optional
	NetworkACL *NetworkACLRef `json:"networkACL,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName={"l2net"}
// +kubebuilder:printcolumn:name="Vpc",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="Cidr",type="string",JSONPath=".spec.cidr"
// +kubebuilder:printcolumn:name="Mtu",type="integer",JSONPath=".status.mtu"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// L2Network is the Schema for the l2networks API.
type L2Network struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   L2NetworkSpec   `json:"spec,omitempty"`
	Status L2NetworkStatus `json:"status,omitempty"`
}

const (
	L2NetworkStatusReady string = "Ready"
)

// +kubebuilder:object:root=true

// L2NetworkList contains a list of L2Network.
type L2NetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []L2Network `json:"items"`
}

func init() {
	SchemeBuilder.Register(&L2Network{}, &L2NetworkList{})
}
