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
	"k8s.io/apimachinery/pkg/types"
)

// NetworkInterfaceSpec defines the desired state of NetworkInterface.
type NetworkInterfaceSpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Subnet string `json:"subnet"`

	// Address requests a specific primary address. When empty, Juneau
	// allocates one from the referenced Subnet.
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

	// AttachmentRef selects the single pod-scoped attachment that may use
	// this interface. The owning workload controller updates this reference
	// as Pods are replaced; the interface and its address remain stable.
	// +optional
	AttachmentRef *NetworkInterfaceAttachmentReference `json:"attachmentRef,omitempty"`
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

// NetworkInterfaceAttachmentReference identifies an attachment by name and
// UID so a deleted and re-created object cannot inherit an existing binding.
type NetworkInterfaceAttachmentReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +required
	UID types.UID `json:"uid"`
}

type NetworkRoute struct {
	Dst string `json:"dst"`
	GW  string `json:"gw"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName={"interface","iface","nwinterface","nwiface"}
// +kubebuilder:printcolumn:name="Subnet",type="string",JSONPath=".spec.subnet"
// +kubebuilder:printcolumn:name="Address",type="string",JSONPath=".status.address"
// +kubebuilder:printcolumn:name="Attachment",type="string",JSONPath=".spec.attachmentRef.name"
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
