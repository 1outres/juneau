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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// NetworkInterfaceAttachmentSpec binds one persistent NetworkInterface to a
// concrete Pod interface on a node. Attachments are owned by Pods and are
// replaced whenever the Pod is replaced.
type NetworkInterfaceAttachmentSpec struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	NetworkInterfaceRef string `json:"networkInterfaceRef"`

	// +required
	PodRef NetworkInterfaceAttachmentPodReference `json:"podRef"`

	// +required
	// +kubebuilder:validation:MinLength=1
	NodeName string `json:"nodeName"`
}

type NetworkInterfaceAttachmentPodReference struct {
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

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName={"niattach","nia"}
// +kubebuilder:printcolumn:name="Interface",type="string",JSONPath=".spec.networkInterfaceRef"
// +kubebuilder:printcolumn:name="Pod",type="string",JSONPath=".spec.podRef.name"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"

// NetworkInterfaceAttachment is the Schema for pod-scoped interface bindings.
type NetworkInterfaceAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NetworkInterfaceAttachmentSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkInterfaceAttachmentList contains a list of attachments.
type NetworkInterfaceAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkInterfaceAttachment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkInterfaceAttachment{}, &NetworkInterfaceAttachmentList{})
}
