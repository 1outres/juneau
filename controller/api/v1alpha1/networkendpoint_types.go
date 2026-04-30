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

// EndpointKind enumerates the kinds of network endpoints that can join
// an L2 segment (Subnet) on the data plane.
//
// The data plane reconcilers (arp/fdb/pod-iface/attacher) are
// kind-agnostic; Kind exists for observability, validation
// (kind-specific required fields), and provider-specific bookkeeping
// (e.g. PodRef back-pointer for Kind=Pod).
// +kubebuilder:validation:Enum=Pod;Node;ServiceNAT
type EndpointKind string

const (
	// EndpointKindPod represents a per-Pod veth-attached endpoint
	// created by the CNI ADD path.
	EndpointKindPod EndpointKind = "Pod"

	// EndpointKindNode represents the per-Node "juneau_node" pseudo-pod
	// veth that lets the host stack participate in the default Subnet's
	// L2 overlay. Created by the daemon during bootstrap.
	EndpointKindNode EndpointKind = "Node"

	// EndpointKindServiceNAT represents the per-Node SNAT source IP
	// used by the shared-Service path. Unlike Pod / Node endpoints there
	// is no backing veth: the IP only ever appears as the destination of
	// reply traffic from default-Vpc backends. The data plane resolves
	// it via arp/fdb to deliver the reply to the originating Node, where
	// the VXLAN-ingress hook reverses the SNAT and forwards the packet
	// to the caller Pod via conntrack lookup.
	EndpointKindServiceNAT EndpointKind = "ServiceNAT"
)

// NetworkEndpointAttachment describes the local kernel iface that
// realizes this endpoint on Spec.NodeName. Populated by the daemon
// running on Spec.NodeName after the veth is created. Other nodes'
// daemons read the rest of Spec but ignore Attachment (ifindex is
// meaningless across nodes).
type NetworkEndpointAttachment struct {
	// Ifindex is the BPF-attached side of the veth pair on Spec.NodeName.
	// +required
	// +kubebuilder:validation:Minimum=1
	Ifindex int `json:"ifindex"`

	// HostMACAddress is the MAC of the host-side veth peer (the side
	// that faces the host network stack on Spec.NodeName). Used by the
	// data plane to populate ifindex_host_mac.
	// +required
	// +kubebuilder:validation:MinLength=1
	HostMACAddress string `json:"hostMACAddress"`
}

// NetworkEndpointSpec defines the desired state of NetworkEndpoint.
type NetworkEndpointSpec struct {
	// Kind identifies what produced this endpoint.
	// +required
	Kind EndpointKind `json:"kind"`

	// NodeName pins the endpoint to a specific node. The daemon on
	// this node owns the Attachment fields.
	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`

	// Subnet is the L2 segment this endpoint participates in.
	// +required
	// +kubebuilder:validation:MinLength=1
	Subnet string `json:"subnet"`

	// Address is the L3 identity in CIDR form (e.g. "10.0.0.5/24").
	// +optional
	Address string `json:"address,omitempty"`

	// MACAddress is the L2 identity used as the destination MAC for
	// this endpoint on the overlay. Always required for endpoints that
	// participate in arp/fdb (i.e. all Kind=Pod and Kind=Node).
	// +optional
	MACAddress string `json:"macAddress,omitempty"`

	// Attachment describes the local kernel iface that backs this
	// endpoint on Spec.NodeName. Populated by the local daemon.
	// +optional
	Attachment *NetworkEndpointAttachment `json:"attachment,omitempty"`

	// PodRef is required when Kind=Pod and otherwise omitted.
	// +optional
	PodRef *NetworkEndpointPodReference `json:"podRef,omitempty"`
}

// NetworkEndpointStatus defines the observed state of NetworkEndpoint.
type NetworkEndpointStatus struct {
	// NodeIP is the underlay IP of Spec.NodeName, populated by the
	// controller. Used by remote daemons to populate fdb VTEP entries.
	NodeIP string `json:"nodeIP,omitempty"`
}

type NetworkEndpointPodReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Interface string `json:"interface"`
	// +required
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={"nwep"}
// +kubebuilder:printcolumn:name="Kind",type="string",JSONPath=".spec.kind"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Subnet",type="string",JSONPath=".spec.subnet"
// +kubebuilder:printcolumn:name="Address",type="string",JSONPath=".spec.address"

// NetworkEndpoint is the Schema for the networkendpoints API.
type NetworkEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkEndpointSpec   `json:"spec,omitempty"`
	Status NetworkEndpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkEndpointList contains a list of NetworkEndpoint.
type NetworkEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkEndpoint{}, &NetworkEndpointList{})
}
