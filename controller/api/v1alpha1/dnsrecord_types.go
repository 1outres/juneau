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

// DNSRecordType is a DNS resource record type supported by Juneau. Only A is supported.
type DNSRecordType string

const (
	// DNSRecordTypeA publishes an IPv4 address RRset. It is the only supported type.
	DNSRecordTypeA DNSRecordType = "A"

	// DNSRecordConditionReady reports whether a DNSRecord can serve its current generation.
	DNSRecordConditionReady = "Ready"
)

// DNSNetworkInterfaceSource refers to one namespaced NetworkInterface.
type DNSNetworkInterfaceSource struct {
	// Namespace is the namespace of the NetworkInterface.
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// Name is the name of the NetworkInterface.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// DNSVpcEndpointSource refers to one cluster-scoped VpcEndpoint.
type DNSVpcEndpointSource struct {
	// Name is the name of the VpcEndpoint.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// DNSPodSelectorSource resolves one interface on every eligible selected Pod.
// +kubebuilder:validation:XValidation:rule="(has(self.selector.matchLabels) && size(self.selector.matchLabels) > 0) || (has(self.selector.matchExpressions) && size(self.selector.matchExpressions) > 0)",message="selector must not be empty"
type DNSPodSelectorSource struct {
	// Namespace limits Pod selection to one namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// Interface names the Pod interface whose address is published.
	// +required
	// +kubebuilder:validation:MinLength=1
	Interface string `json:"interface"`

	// Selector is a non-empty Kubernetes label selector for Pods.
	// +required
	Selector metav1.LabelSelector `json:"selector"`
}

// DNSRecordSource is one address source in an A RRset. Exactly one source kind
// must be set. Different entries in DNSRecordSpec.Sources can use different kinds.
// +kubebuilder:validation:XValidation:rule="[has(self.ip), has(self.networkInterface), has(self.vpcEndpoint), has(self.podSelector)].filter(x, x).size() == 1",message="set exactly one of ip, networkInterface, vpcEndpoint and podSelector"
type DNSRecordSource struct {
	// IP is one literal IPv4 address. Juneau does not check its reachability.
	// +optional
	// +kubebuilder:validation:Format=ipv4
	IP *string `json:"ip,omitempty"`

	// NetworkInterface selects one namespaced NetworkInterface.
	// +optional
	NetworkInterface *DNSNetworkInterfaceSource `json:"networkInterface,omitempty"`

	// VpcEndpoint selects one cluster-scoped VpcEndpoint.
	// +optional
	VpcEndpoint *DNSVpcEndpointSource `json:"vpcEndpoint,omitempty"`

	// PodSelector selects an interface from each eligible matching Pod.
	// +optional
	PodSelector *DNSPodSelectorSource `json:"podSelector,omitempty"`
}

// DNSRecordSpec defines one private DNS A RRset.
type DNSRecordSpec struct {
	// Zone names the existing DNSZone that owns this record. This field cannot
	// be changed after creation.
	// +required
	// +kubebuilder:validation:MinLength=1
	Zone string `json:"zone"`

	// Name is a lowercase name relative to the zone, or @ for the zone apex.
	// Wildcards and trailing dots are not allowed. This field cannot be changed
	// after creation.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^(@|[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*)$`
	Name string `json:"name"`

	// Type is the DNS record type. Only A is supported. This field cannot be
	// changed after creation.
	// +required
	// +kubebuilder:validation:Enum=A
	Type DNSRecordType `json:"type"`

	// TTL is the answer lifetime in seconds. It defaults to 30 and must be from
	// 1 through 86400.
	// +optional
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=86400
	TTL *int32 `json:"ttl,omitempty"`

	// Sources contains from 1 through 100 address sources. Every entry must set
	// exactly one source kind.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Sources []DNSRecordSource `json:"sources"`
}

// DNSRecordStatus defines the observed state of DNSRecord.
type DNSRecordStatus struct {
	// ObservedGeneration is the DNSRecord generation used to compute this status.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Addresses is the deduplicated set of resolved IPv4 addresses. An empty set
	// is valid. A record can contain at most 100 addresses.
	// +kubebuilder:validation:MaxItems=100
	// +listType=set
	Addresses []string `json:"addresses,omitempty"`

	// Conditions contains Ready. Ready is false for a zone or record conflict,
	// an invalid required source, or a result that exceeds the address limit.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Zone",type="string",JSONPath=".spec.zone"
// +kubebuilder:printcolumn:name="Name",type="string",JSONPath=".spec.name"
// +kubebuilder:printcolumn:name="Type",type="string",JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// DNSRecord is a cluster-scoped private DNS A RRset in one DNSZone.
type DNSRecord struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DNSRecordSpec   `json:"spec,omitempty"`
	Status DNSRecordStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DNSRecordList contains a list of DNSRecord.
type DNSRecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DNSRecord `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DNSRecord{}, &DNSRecordList{})
}
