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

// NetworkInterfaceSpec defines the desired state of NetworkInterface.
// +kubebuilder:validation:XValidation:rule="[has(self.subnet), has(self.l2Network), has(self.elasticIP)].filter(x, x).size() == 1",message="set exactly one of spec.subnet, spec.l2Network and spec.elasticIP"
// +kubebuilder:validation:XValidation:rule="!has(self.elasticIP) || ((!has(self.address) || size(self.address) == 0) && (!has(self.securityGroups) || size(self.securityGroups) == 0))",message="spec.address and spec.securityGroups must be empty when spec.elasticIP is set"
type NetworkInterfaceSpec struct {
	// +required
	PodRef NetworkInterfacePodReference `json:"podRef"`

	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`

	// Subnet is the Subnet this interface joins. Exactly one of Subnet,
	// L2Network and ElasticIP is set.
	// +optional
	// +kubebuilder:validation:MinLength=1
	Subnet string `json:"subnet,omitempty"`

	// L2Network is the L2Network this interface joins. Exactly one of
	// Subnet, L2Network and ElasticIP is set. An L2Network without a CIDR
	// hands out no address at all, so an interface on one becomes
	// Allocated with an empty status.address.
	// +optional
	// +kubebuilder:validation:MinLength=1
	L2Network string `json:"l2Network,omitempty"`

	// ElasticIP names an ElasticIP in the namespace of this interface.
	// The interface carries the address of that ElasticIP directly, with
	// no NAT in between, and joins no Vpc. Exactly one of Subnet,
	// L2Network and ElasticIP is set.
	//
	// The ElasticIP owns the address, so such an interface has no
	// AllocationClaim, no Address and no SecurityGroups. Its
	// status.address is the ElasticIP address as a /32. One ElasticIP is
	// carried by at most one interface at a time.
	// +optional
	// +kubebuilder:validation:MinLength=1
	ElasticIP string `json:"elasticIP,omitempty"`

	// +optional
	Address string `json:"address,omitempty"`

	// SecurityGroups lists SecurityGroup resources whose rules apply
	// to this interface. Order is irrelevant; rules from all listed
	// SGs are unioned. An empty / nil list means "no SG enforcement"
	// unless the owning Vpc has spec.enforceSecurityGroups=true, in
	// which case Pod admission rejects unattached Pods.
	//
	// All referenced SGs must belong to the same Vpc as the network this
	// NetworkInterface joins. Webhook validation enforces this.
	// +optional
	// +kubebuilder:validation:MaxItems=2
	// +listType=set
	SecurityGroups []string `json:"securityGroups,omitempty"`

	// AllocationIdentity keeps the allocated address attached to the
	// workload instead of the pod name. Pods that get a new name on every
	// restart (KubeVirt virt-launcher pods, for example) set this. Two
	// interfaces that share an identity share the address reservation, so
	// the value must be unique per workload within the namespace. Must be a
	// DNS-1123 subdomain.
	//
	// An interface on an ElasticIP allocates nothing. There the identity
	// only lets a new interface of the same workload ask for the
	// ElasticIP while the old interface still holds it.
	// +optional
	AllocationIdentity string `json:"allocationIdentity,omitempty"`

	// RetainWhile keeps the allocated address reserved for as long as the
	// referenced object exists, even after this interface is gone. A
	// virt-launcher pod points at its VirtualMachine, so a stopped virtual
	// machine keeps its address until the machine itself is deleted. When
	// unset, the reservation starts expiring as soon as the interface is
	// deleted.
	// +optional
	RetainWhile *RetainReference `json:"retainWhile,omitempty"`
}

// NetworkInterfaceStatus defines the observed state of NetworkInterface.
type NetworkInterfaceStatus struct {
	Conditions         []metav1.Condition    `json:"conditions,omitempty"`
	ObservedGeneration int64                 `json:"observedGeneration,omitempty"`
	Phase              NetworkInterfacePhase `json:"phase,omitempty"`

	// AllocationClaim names the cluster-scoped AllocationClaim that the
	// reconciler maintains for this interface's IP reservation. Useful
	// only for debugging — daemon/CNI consumers should rely on Address.
	AllocationClaim string         `json:"allocationClaim,omitempty"`
	Address         string         `json:"address,omitempty"`
	Routes          []NetworkRoute `json:"routes,omitempty"`

	// Rules lists the policy routing rules the CNI server adds to the pod
	// network namespace for this interface. An extra interface on an
	// ElasticIP uses one to send traffic from its address to its own
	// route table.
	Rules []NetworkRoutingRule `json:"rules,omitempty"`

	// EffectiveSecurityGroups echoes spec.securityGroups after the
	// controller resolved them (filtered by existence + same-Vpc) and
	// includes the assigned GroupID for each. Daemon reads this list
	// rather than spec, so a stale/dangling spec entry never causes a
	// blackhole.
	EffectiveSecurityGroups []NetworkInterfaceEffectiveSG `json:"effectiveSecurityGroups,omitempty"`
}

// NetworkInterfaceEffectiveSG is a single resolved SecurityGroup
// reference. Daemon-side maps key off GroupID, never the name.
type NetworkInterfaceEffectiveSG struct {
	Name    string `json:"name"`
	GroupID uint32 `json:"groupID"`
}

type NetworkInterfacePodReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Interface string `json:"interface"`
}

// NetworkRoute is one route the CNI server adds to the pod network
// namespace, through the interface it is listed on.
type NetworkRoute struct {
	Dst string `json:"dst"`
	GW  string `json:"gw"`

	// OnLink says GW is on the link even though no address of the
	// interface covers it. An interface on an ElasticIP holds only a /32
	// and reaches PodElasticIPGateway this way.
	// +optional
	OnLink bool `json:"onLink,omitempty"`

	// Table is the route table the route goes into. Zero means the main
	// table. See PodElasticIPRouteTable for the numbers Juneau uses.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	Table int64 `json:"table,omitempty"`
}

// NetworkRoutingRule is one policy routing rule the CNI server adds to the
// pod network namespace.
type NetworkRoutingRule struct {
	// From is the source prefix the rule matches, in CIDR form.
	// +required
	// +kubebuilder:validation:MinLength=1
	From string `json:"from"`

	// Table is the route table a packet that matches is looked up in.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	Table int64 `json:"table"`

	// Priority orders the rule among the other rules of the network
	// namespace. A lower number is looked at first.
	// +required
	// +kubebuilder:validation:Minimum=0
	Priority int32 `json:"priority"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={"interface","iface","nwinterface","nwiface"}
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Subnet",type="string",JSONPath=".spec.subnet"
// +kubebuilder:printcolumn:name="L2Network",type="string",JSONPath=".spec.l2Network"
// +kubebuilder:printcolumn:name="ElasticIP",type="string",JSONPath=".spec.elasticIP"
// +kubebuilder:printcolumn:name="Address",type="string",JSONPath=".status.address"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"

// NetworkInterface is the Schema for the networkinterfaces API.
type NetworkInterface struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkInterfaceSpec   `json:"spec,omitempty"`
	Status NetworkInterfaceStatus `json:"status,omitempty"`
}

type NetworkInterfacePhase string

const (
	NetworkInterfaceStatusAllocated string = "Allocated"
	NetworkInterfaceStatusReady     string = "Ready"

	NetworkInterfacePhasePending   NetworkInterfacePhase = "Pending"
	NetworkInterfacePhaseAllocated NetworkInterfacePhase = "Allocated"
	NetworkInterfacePhaseReady     NetworkInterfacePhase = "Ready"
	NetworkInterfacePhaseFailed    NetworkInterfacePhase = "Failed"
)

// +kubebuilder:object:root=true

// NetworkInterfaceList contains a list of NetworkInterface.
type NetworkInterfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkInterface `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkInterface{}, &NetworkInterfaceList{})
}
