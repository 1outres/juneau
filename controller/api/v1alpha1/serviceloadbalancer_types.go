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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceLoadBalancerSpec describes the desired LoadBalancer state
// derived from a Kubernetes Service.
//
// A ServiceLoadBalancer is owned by exactly one Service in the same
// namespace. The controller uses ServiceRef.Name plus the resource's
// own namespace to resolve the parent Service; the resource is named
// deterministically from the parent Service so that multiple
// reconcilers can converge without racing on creation.
type ServiceLoadBalancerSpec struct {
	// ServiceRef points at the Kubernetes Service that owns this
	// resource. The Service must live in the same namespace as the
	// ServiceLoadBalancer; cross-namespace references are rejected at
	// admission time.
	// +required
	ServiceRef ServiceLoadBalancerServiceReference `json:"serviceRef"`

	// ExternalNetwork selects the cluster-scoped ExternalNetwork from
	// which the VIP is allocated. The referenced ExternalNetwork must
	// exist and must declare at least one AddressPool.
	// +required
	// +kubebuilder:validation:MinLength=1
	ExternalNetwork string `json:"externalNetwork"`

	// RequestedIP optionally pins a specific IPv4 address. The address
	// must fall inside one of the AddressPools attached to the
	// referenced ExternalNetwork. When unset (empty string) the
	// controller picks the first available address.
	// +optional
	RequestedIP string `json:"requestedIP,omitempty"`
}

// ServiceLoadBalancerServiceReference identifies the parent Service.
//
// The reference is intentionally minimal: ServiceLoadBalancer is
// always co-located with its Service, so the API does not surface a
// Namespace or Group/Kind field that could drift from reality.
type ServiceLoadBalancerServiceReference struct {
	// Name of the Service in the same namespace as this resource.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// ServiceLoadBalancerPhase summarises the high-level lifecycle state.
//
// The phase is informational and is intended for human consumption
// (kubectl printer columns and dashboards). Programmatic logic should
// use Conditions, which carry stable reason/status semantics.
type ServiceLoadBalancerPhase string

const (
	// ServiceLoadBalancerPhasePending means the controller has accepted
	// the resource but has not yet allocated a VIP.
	ServiceLoadBalancerPhasePending ServiceLoadBalancerPhase = "Pending"
	// ServiceLoadBalancerPhaseAllocated means a VIP has been allocated
	// but the dataplane (advertising nodes / per-node programming) is
	// not yet ready.
	ServiceLoadBalancerPhaseAllocated ServiceLoadBalancerPhase = "Allocated"
	// ServiceLoadBalancerPhaseReady means a VIP is allocated and at
	// least one node is currently advertising it.
	ServiceLoadBalancerPhaseReady ServiceLoadBalancerPhase = "Ready"
	// ServiceLoadBalancerPhaseDegraded means a VIP is allocated but no
	// node is currently advertising it (e.g. all backends unready).
	ServiceLoadBalancerPhaseDegraded ServiceLoadBalancerPhase = "Degraded"
	// ServiceLoadBalancerPhaseError means the controller hit a
	// non-recoverable error such as an invalid ExternalNetwork or
	// requested IP outside the pool.
	ServiceLoadBalancerPhaseError ServiceLoadBalancerPhase = "Error"
)

// Condition types used on ServiceLoadBalancer.status.conditions.
//
// They are stable, machine-readable strings. Reason values are
// reserved for the specific controllers that own each condition.
const (
	// ServiceLoadBalancerConditionAccepted is True once the controller
	// has fully validated the resource (Service link, ExternalNetwork
	// exists, requestedIP within pool, etc.).
	ServiceLoadBalancerConditionAccepted = "Accepted"
	// ServiceLoadBalancerConditionAllocated is True once a VIP has
	// been allocated and recorded in Status.VIP.
	ServiceLoadBalancerConditionAllocated = "Allocated"
	// ServiceLoadBalancerConditionAvailable is True when at least one
	// node is currently eligible to advertise the VIP. It flips to
	// False with reason NoReadyBackends when all backends are gone.
	ServiceLoadBalancerConditionAvailable = "Available"
	// ServiceLoadBalancerConditionProgrammed is True when the
	// dataplane on every advertising node has accepted the desired
	// configuration.
	ServiceLoadBalancerConditionProgrammed = "Programmed"
)

// Condition reasons. Free-form strings are still permitted, but the
// constants below are the canonical set the controller emits and the
// values external observers (kubectl-juneau, tests) can match against.
const (
	ServiceLoadBalancerReasonAllocated         = "Allocated"
	ServiceLoadBalancerReasonPoolExhausted     = "PoolExhausted"
	ServiceLoadBalancerReasonInvalidConfig     = "InvalidConfig"
	ServiceLoadBalancerReasonExternalNetwork   = "ExternalNetworkUnavailable"
	ServiceLoadBalancerReasonNoReadyBackends   = "NoReadyBackends"
	ServiceLoadBalancerReasonReady             = "Ready"
	ServiceLoadBalancerReasonProgramming       = "Programming"
	ServiceLoadBalancerReasonAwaitingDataplane = "AwaitingDataplane"
)

// ServiceLoadBalancerPort mirrors the Service port that this
// LoadBalancer exposes externally. The port list is recomputed every
// reconcile from the parent Service so it stays in sync.
type ServiceLoadBalancerPort struct {
	// Name of the port. May be empty if the parent Service uses a
	// single unnamed port.
	// +optional
	Name string `json:"name,omitempty"`

	// Protocol is the L4 protocol. Only TCP and UDP are supported in
	// the initial release; SCTP and other values are rejected at
	// admission time.
	// +required
	Protocol corev1.Protocol `json:"protocol"`

	// Port is the externally-exposed port that clients connect to on
	// the VIP.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// TargetPort is the port on the backend Pod. When the parent
	// Service uses a string targetPort, the controller resolves it
	// against the backend EndpointSlice and writes the integer port
	// here so dataplane consumers do not need to re-resolve names.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	TargetPort int32 `json:"targetPort"`
}

// ServiceLoadBalancerBackendSummary is a small aggregate of backend
// endpoint state. It exists so kubectl-juneau and dashboards can
// surface fleet health without re-listing EndpointSlices.
type ServiceLoadBalancerBackendSummary struct {
	// TotalReady is the number of ready, serving, non-terminating
	// endpoints across the whole Service.
	// +optional
	TotalReady int32 `json:"totalReady"`

	// LocalReadyNodes is the number of distinct nodes that have at
	// least one ready local endpoint. It is the cardinality of the
	// AdvertisingNodes set when externalTrafficPolicy=Local.
	// +optional
	LocalReadyNodes int32 `json:"localReadyNodes"`
}

// ServiceLoadBalancerStatus reports the observed state derived from
// the parent Service, EndpointSlices, and the allocation pipeline.
type ServiceLoadBalancerStatus struct {
	// ObservedGeneration is the .metadata.generation the status
	// reflects. Status consumers should ignore status fields when
	// observedGeneration < .metadata.generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase is a coarse human-readable lifecycle indicator. See the
	// ServiceLoadBalancerPhase constants for the full set.
	// +optional
	Phase ServiceLoadBalancerPhase `json:"phase,omitempty"`

	// VIP is the allocated external IP address. Empty until allocation
	// succeeds. Once written, the controller treats VIP as immutable
	// for the lifetime of the resource.
	// +optional
	VIP string `json:"vip,omitempty"`

	// AddressPool records which AddressPool the VIP was drawn from.
	// Mainly informational; downstream consumers should not assume
	// pool membership without re-resolving against the API.
	// +optional
	AddressPool string `json:"addressPool,omitempty"`

	// Ports is the canonical list of (port, protocol, targetPort)
	// triples derived from the parent Service. The list is sorted by
	// (Port, Protocol) so consumers see deterministic output.
	// +optional
	// +listType=atomic
	Ports []ServiceLoadBalancerPort `json:"ports,omitempty"`

	// AdvertisingNodes lists Kubernetes node names that currently
	// have at least one ready local endpoint and may therefore
	// advertise the VIP via BGP. The list is sorted lexicographically
	// for stability.
	// +optional
	// +listType=set
	AdvertisingNodes []string `json:"advertisingNodes,omitempty"`

	// BackendSummary aggregates endpoint-level fleet health for
	// dashboards.
	// +optional
	BackendSummary ServiceLoadBalancerBackendSummary `json:"backendSummary,omitempty"`

	// AllocationClaimName names the AllocationClaim that owns the VIP
	// allocation. Recorded so that finalization and observability can
	// follow the claim without having to re-derive the name.
	// +optional
	AllocationClaimName string `json:"allocationClaimName,omitempty"`

	// Conditions track fine-grained observable state. See the
	// ServiceLoadBalancerCondition* constants for the canonical set.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=slb
// +kubebuilder:printcolumn:name="Service",type="string",JSONPath=".spec.serviceRef.name"
// +kubebuilder:printcolumn:name="ExternalNetwork",type="string",JSONPath=".spec.externalNetwork"
// +kubebuilder:printcolumn:name="VIP",type="string",JSONPath=".status.vip"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="AdvertisingNodes",type="integer",JSONPath=".status.backendSummary.localReadyNodes"
// +kubebuilder:printcolumn:name="Allocated",type="string",JSONPath=".status.conditions[?(@.type==\"Allocated\")].status"
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].status"

// ServiceLoadBalancer is the Schema for Juneau-managed Service
// LoadBalancer state. Each resource normalises the desired and
// observed state derived from a Kubernetes Service so that the
// controller, daemon, BGP speaker, and CLI tooling do not each
// re-interpret Service annotations independently.
type ServiceLoadBalancer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceLoadBalancerSpec   `json:"spec,omitempty"`
	Status ServiceLoadBalancerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceLoadBalancerList contains a list of ServiceLoadBalancer.
type ServiceLoadBalancerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceLoadBalancer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ServiceLoadBalancer{}, &ServiceLoadBalancerList{})
}
