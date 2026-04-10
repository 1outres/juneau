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
	Peer      string       `json:"peer,omitempty"`
	State     string       `json:"state,omitempty"`
	UpSince   *metav1.Time `json:"upSince,omitempty"`
	LastError string       `json:"lastError,omitempty"`
}

type BGPNodeStateAdvertisement struct {
	AddressPool  string       `json:"addressPool,omitempty"`
	Prefixes     int32        `json:"prefixes,omitempty"`
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
