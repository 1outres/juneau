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
	PodRef NetworkInterfacePodReference `json:"podRef"`

	NodeName string `json:"nodeName"`

	Subnet  string `json:"subnet"`
	Address string `json:"address,omitempty"`
}

// NetworkInterfaceStatus defines the observed state of NetworkInterface.
type NetworkInterfaceStatus struct {
	Conditions         []metav1.Condition    `json:"conditions,omitempty"`
	ObservedGeneration int64                 `json:"observedGeneration,omitempty"`
	Phase              NetworkInterfacePhase `json:"phase,omitempty"`

	IPLease string         `json:"ipLease,omitempty"`
	Address string         `json:"address,omitempty"`
	Routes  []NetworkRoute `json:"routes,omitempty"`
}

type NetworkInterfacePodReference struct {
	UID       string `json:"uid"`
	Name      string `json:"name"`
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
