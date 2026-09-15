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

// DNSZoneSpec defines one private DNS suffix in a Vpc.
// +kubebuilder:validation:XValidation:rule="self.domain != 'cluster.local' && !self.domain.endsWith('.cluster.local')",message="cluster.local and its descendants are reserved"
type DNSZoneSpec struct {
	// Vpc names the Vpc for which this zone is authoritative. The Vpc must
	// exist. This field cannot be changed after creation.
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`

	// Domain is a lowercase DNS-1123 suffix without a trailing dot. Parent
	// and child zones are allowed, and the longest matching suffix wins.
	// The cluster.local name and its descendants are reserved. A Vpc can have only
	// one zone for a domain, while another Vpc can reuse the same domain.
	// This field cannot be changed after creation.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`
	Domain string `json:"domain"`
}

// DNSZoneStatus defines the observed state of DNSZone.
type DNSZoneStatus struct {
	// ObservedGeneration is the DNSZone generation used to compute this status.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions contains Ready. A zone is Ready when its Vpc exists and no
	// other zone in that Vpc uses the same domain.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DNSZoneConditionReady reports whether a DNSZone can serve its current generation.
const DNSZoneConditionReady = "Ready"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Vpc",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.domain"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// DNSZone is a cluster-scoped private authoritative DNS zone for one Vpc.
type DNSZone struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DNSZoneSpec   `json:"spec,omitempty"`
	Status DNSZoneStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DNSZoneList contains a list of DNSZone.
type DNSZoneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DNSZone `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DNSZone{}, &DNSZoneList{})
}
