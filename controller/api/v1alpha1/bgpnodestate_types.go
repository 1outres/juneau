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

// BGPNodeStateSpec defines the desired state of BGPNodeState.
type BGPNodeStateSpec struct {
}

// BGPNodeStateStatus defines the observed state of BGPNodeState.
type BGPNodeStateStatus struct {
	Heartbeat      *metav1.Time                `json:"heartbeat,omitempty"`
	BGPSessions    []BGPNodeStateSession       `json:"bgpSessions,omitempty"`
	Advertisements []BGPNodeStateAdvertisement `json:"advertisements,omitempty"`
	Conditions     []metav1.Condition          `json:"conditions,omitempty"`
	Errors         []BGPNodeStateError         `json:"errors,omitempty"`
}

type BGPNodeStateSession struct {
	// PeerAddress is the BGP peer's IP address as observed on the wire via BMP.
	// Always set.
	PeerAddress string `json:"peerAddress,omitempty"`
	// PeerName is the BGPPeer resource name that configured this session.
	// Empty when the BGPPeer resource could not be resolved (e.g. deleted
	// but session still active, or bird.conf not yet reloaded).
	PeerName  string       `json:"peerName,omitempty"`
	State     string       `json:"state,omitempty"`
	UpSince   *metav1.Time `json:"upSince,omitempty"`
	LastError string       `json:"lastError,omitempty"`
}

type BGPNodeStateAdvertisement struct {
	AddressPool string `json:"addressPool,omitempty"`
	// Prefixes is the set of CIDRs that bgp-speaker intends to advertise from
	// this AddressPool. Derived from AddressPool.spec.addresses at reconcile
	// time, not observed on the wire (BIRD BMP does not expose adj-RIB-out).
	// +listType=set
	Prefixes     []string     `json:"prefixes,omitempty"`
	LastSyncedAt *metav1.Time `json:"lastSyncedAt,omitempty"`
}

type BGPNodeStateError struct {
	ResourceKind string       `json:"resourceKind,omitempty"`
	ResourceName string       `json:"resourceName,omitempty"`
	Message      string       `json:"message,omitempty"`
	LastSeen     *metav1.Time `json:"lastSeen,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Bird",type=string,JSONPath=`.status.conditions[?(@.type=="BirdRunning")].status`
// +kubebuilder:printcolumn:name="BMP",type=string,JSONPath=`.status.conditions[?(@.type=="BMPConnected")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Heartbeat",type=date,JSONPath=`.status.heartbeat`,priority=1

// BGPNodeState is the Schema for the bgpnodestates API.
type BGPNodeState struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPNodeStateSpec   `json:"spec,omitempty"`
	Status BGPNodeStateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BGPNodeStateList contains a list of BGPNodeState.
type BGPNodeStateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPNodeState `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPNodeState{}, &BGPNodeStateList{})
}
