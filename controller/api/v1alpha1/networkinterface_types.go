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
type NetworkInterfaceSpec struct {
	// +required
	PodRef NetworkInterfacePodReference `json:"podRef"`

	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`

	// +required
	// +kubebuilder:validation:MinLength=1
	Subnet string `json:"subnet"`
	// +optional
	Address string `json:"address,omitempty"`

	// SecurityGroups lists SecurityGroup resources whose rules apply
	// to this interface. Order is irrelevant; rules from all listed
	// SGs are unioned. An empty / nil list means "no SG enforcement"
	// unless the owning Vpc has spec.enforceSecurityGroups=true, in
	// which case Pod admission rejects unattached Pods.
	//
	// All referenced SGs must belong to the same Vpc as this
	// NetworkInterface's Subnet. Webhook validation enforces this.
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

type NetworkRoute struct {
	Dst string `json:"dst"`
	GW  string `json:"gw"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={"interface","iface","nwinterface","nwiface"}
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Subnet",type="string",JSONPath=".spec.subnet"
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
