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
	Vpc  string `json:"vpc"`
	CIDR string `json:"cidr"`

	// RouteTable selects which RouteTable governs traffic from Pods in
	// this Subnet. Empty means "use the owning Vpc's main RouteTable",
	// which preserves the original behaviour. The referenced RouteTable
	// must belong to the same Vpc.
	// +optional
	RouteTable string `json:"routeTable,omitempty"`

	// NetworkACL names the NetworkACL applied at this Subnet's
	// boundary. The referenced ACL must belong to the same Vpc as the
	// Subnet (webhook-enforced). Empty means "no ACL" — the Subnet
	// boundary does not enforce policy and traffic flows straight to
	// the per-Pod SecurityGroup layer.
	//
	// Mutability: the field is mutable. Switching the reference (or
	// clearing it) re-converges the Subnet status and triggers
	// daemon-side CT invalidation so flows pick up the new policy on
	// their next packet.
	// +optional
	NetworkACL string `json:"networkACL,omitempty"`
}

// SubnetStatus defines the observed state of Subnet.
type SubnetStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	VNI uint32 `json:"vni,omitempty"`

	Gateway    string `json:"gateway,omitempty"`
	GatewayMAC string `json:"gatewayMAC,omitempty"`

	// DNS is the per-Subnet virtual DNS resolver IP (the second usable
	// address in the prefix, conventionally `.2`). The juneau daemon
	// terminates UDP/53 and TCP/53 destined for this address inside its
	// virtual service plane and never bridges it to the underlay. Empty
	// when the Subnet's prefix has no usable `.2`.
	DNS string `json:"dns,omitempty"`

	// DNSMAC is the locally-administered Ethernet address that ARP for
	// the DNS VIP resolves to. Distinct from GatewayMAC so the data
	// plane can demultiplex virtual-service traffic by destination MAC
	// before consulting the FIB. Empty when DNS is empty.
	DNSMAC string `json:"dnsMAC,omitempty"`

	// NetworkACL mirrors the resolved spec.networkACL reference. It
	// carries the cluster-wide ACLID the daemon writes into the BPF
	// subnet_map plus the ACL's RulesetVersion at the time the
	// reference was resolved. Empty (nil) when spec.networkACL is
	// unset or the named ACL does not yet exist.
	// +optional
	NetworkACL *NetworkACLRef `json:"networkACL,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Vpc",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="Cidr",type="string",JSONPath=".spec.cidr"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// Subnet is the Schema for the subnets API.
type Subnet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SubnetSpec   `json:"spec,omitempty"`
	Status SubnetStatus `json:"status,omitempty"`
}

const (
	SubnetStatusReady string = "Ready"
)

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
