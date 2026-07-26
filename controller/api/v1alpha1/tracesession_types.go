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

// TraceSession is a temporary, cluster-scoped coordination object that
// activates dataplane tracing across every juneaud node for a single
// debugging session. The object is created by `kubectl juneau trace`
// for the lifetime of the trace and deleted on exit; daemons watch
// TraceSession resources, program local BPF trace maps, stream events
// to kubectl, and remove their dataplane state on delete or expiry.
//
// TraceSession is intentionally ephemeral. The default workflow keeps
// detailed events out of CRD status entirely — events flow over a
// dedicated debug gRPC channel directly from the daemon to kubectl.
// Status only carries coarse coordination state (phase, observed
// nodes) so reconciliation stays cheap even with many concurrent
// sessions.
//
// `spec.expiresAt` is mandatory: it bounds dataplane state if kubectl
// crashes between create and delete. Daemons treat any session past
// its expiry time as deleted and tear down local trace state even if
// the CRD has not yet been garbage-collected by the API server.

// TraceMode selects whether a trace session injects probe traffic or
// only observes existing traffic that matches the configured tuples.
//
// +kubebuilder:validation:Enum=ActiveProbe;ObserveOnly
type TraceMode string

const (
	// TraceModeActiveProbe asks the daemon (or kubectl) to generate a
	// packet that matches the session's initial tuples. Useful when
	// the actual workload is silent or rarely talks to the target.
	TraceModeActiveProbe TraceMode = "ActiveProbe"
	// TraceModeObserveOnly leaves traffic generation to the workload
	// itself. The daemon programs trace maps but does not synthesize
	// packets. This mode is the only safe option for production
	// debugging where probe injection would be intrusive.
	TraceModeObserveOnly TraceMode = "ObserveOnly"
)

// TraceCaptureLevel selects how much detail the dataplane emits per
// matched packet. Verbose levels increase ringbuf pressure and are
// intended for short, targeted runs.
//
// +kubebuilder:validation:Enum=Summary;Decision;Verbose
type TraceCaptureLevel string

const (
	// TraceCaptureLevelSummary emits a single enter/exit event per
	// hook plus terminal verdicts (drop / pass / redirect). Cheapest;
	// suitable for "did the packet reach node X?" questions.
	TraceCaptureLevelSummary TraceCaptureLevel = "Summary"
	// TraceCaptureLevelDecision adds map-miss and decision-point
	// events (FIB lookup, service backend selection, NAT before/after
	// tuples, policy verdicts). The default.
	TraceCaptureLevelDecision TraceCaptureLevel = "Decision"
	// TraceCaptureLevelVerbose adds packet metadata on every hook
	// entry. Use sparingly: it dominates ringbuf bandwidth.
	TraceCaptureLevelVerbose TraceCaptureLevel = "Verbose"
)

// TraceProtocol selects the IP protocol matched by the session's
// tuples and probe. Mirrors the values used by NetworkACL and
// SecurityGroup so operators can reason about both layers
// consistently.
//
// +kubebuilder:validation:Enum=TCP;UDP;ICMP
type TraceProtocol string

const (
	TraceProtocolTCP  TraceProtocol = "TCP"
	TraceProtocolUDP  TraceProtocol = "UDP"
	TraceProtocolICMP TraceProtocol = "ICMP"
)

// TraceTupleScope qualifies the keyspace a tuple lives in.
//
//   - Host: tuple is meaningful only on the underlay / host network
//     namespace (NAPT outside-side, host-network Service backends).
//   - VPC:  tuple is scoped to a Juneau VPC; vpcID must be set.
//
// +kubebuilder:validation:Enum=Host;VPC
type TraceTupleScope string

const (
	TraceTupleScopeHost TraceTupleScope = "Host"
	TraceTupleScopeVPC  TraceTupleScope = "VPC"
)

// TraceTupleDirection labels a tuple's leg in the flow so daemons and
// kubectl render request vs reply legs from an authoritative signal
// rather than inferring direction from address orientation (which is
// ambiguous under NAT and across VPCs with overlapping Pod CIDRs).
//
// +kubebuilder:validation:Enum=Request;Reply
type TraceTupleDirection string

const (
	// TraceTupleDirectionRequest marks the forward leg (source ->
	// destination). This is the default for kubectl-computed tuples.
	TraceTupleDirectionRequest TraceTupleDirection = "Request"
	// TraceTupleDirectionReply marks the return leg (destination ->
	// source). kubectl installs one Reply mirror per Request tuple —
	// source/destination swapped, ports wildcarded — so reply packets
	// resolve the same trace_id from session start even for flows whose
	// request leg is never observed during the session. The dataplane
	// additionally learns Reply tuples for dynamically discovered /
	// post-NAT legs the moment it matches the corresponding Request.
	TraceTupleDirectionReply TraceTupleDirection = "Reply"
)

// TracePodReference identifies a Pod by namespace + name. Pod UID is
// resolved at session creation by kubectl and not stored in the CRD,
// so a Pod restart between create and observation does not invalidate
// the session.
type TracePodReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// TraceServiceReference identifies a Kubernetes Service by namespace
// + name. The session's destination tuple is computed from the
// Service's ClusterIP at admission time.
type TraceServiceReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// TraceCaptureConfig controls what events the dataplane emits.
// Defaults to a low-overhead "Decision" capture suitable for live
// debugging. Operators can opt in to extra detail at the cost of
// ringbuf pressure.
type TraceCaptureConfig struct {
	// Level selects the per-event verbosity. Defaults to Decision
	// when empty.
	// +optional
	// +kubebuilder:default=Decision
	Level TraceCaptureLevel `json:"level,omitempty"`
	// IncludePacketMeta enriches enter events with packet metadata
	// (TCP flags, ICMP type/code). Costs one extra event field.
	// +optional
	IncludePacketMeta bool `json:"includePacketMeta,omitempty"`
	// IncludeMapMiss surfaces lookup misses in subnet/fdb/arp/fib/
	// service/backend maps. Indispensable for "why did my packet
	// drop?" debugging; cheap to emit because misses are rare in
	// healthy clusters.
	// +optional
	IncludeMapMiss bool `json:"includeMapMiss,omitempty"`
	// IncludePolicy emits NetworkACL and SecurityGroup verdicts as
	// dedicated events so a "policy drop" never has to be inferred
	// from a missing follow-up event.
	// +optional
	IncludePolicy bool `json:"includePolicy,omitempty"`
	// IncludeNAT emits before/after tuples for DNAT, SNAT, NAPT,
	// shared-Service and host-network Service rewrites. Necessary
	// for cross-node propagation: trace_id assignment on the
	// destination node depends on a learned post-NAT tuple.
	// +optional
	IncludeNAT bool `json:"includeNAT,omitempty"`
}

// TraceEndpoint identifies one side of a trace session.
//
// Exactly one of PodRef, ServiceRef or IP must be set. The webhook
// enforces this invariant; daemons treat a missing selector as a
// programming error and skip the session.
//
// Protocol and Port are interpreted relative to the destination side
// only; on the source side they are ignored (a source pod's ephemeral
// port is not known until traffic flows).
type TraceEndpoint struct {
	// PodRef selects a Pod by namespace + name. The Pod must have a
	// Juneau NetworkInterface attached.
	// +optional
	PodRef *TracePodReference `json:"podRef,omitempty"`

	// ServiceRef selects a Kubernetes Service by namespace + name.
	// The destination tuple is computed from the Service's
	// ClusterIP. Use Port + Protocol to disambiguate multi-port
	// Services.
	// +optional
	ServiceRef *TraceServiceReference `json:"serviceRef,omitempty"`

	// IP is a literal IPv4 address (no CIDR). Useful for tracing
	// node-internal IPs, external destinations and bare endpoints
	// that have no Kubernetes object.
	// +optional
	IP string `json:"ip,omitempty"`

	// Protocol applies to the destination side. Required when this
	// endpoint is a session's Destination, ignored on Source.
	// +optional
	Protocol TraceProtocol `json:"protocol,omitempty"`

	// Port applies to the destination side. Required when this
	// endpoint is a session's Destination and Protocol is TCP/UDP;
	// ignored on Source and for ICMP.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`
}

// TraceTuple is a five-tuple plus VPC scope. kubectl pre-computes the
// initial tuples it expects to see and stores them on the spec so
// daemons can program their BPF trace_tuple_map without re-resolving
// CRDs.
type TraceTuple struct {
	// Scope selects the keyspace this tuple belongs to. Determines
	// whether the daemon installs the tuple into the host or VPC
	// trace_tuple_map keyspace.
	// +required
	Scope TraceTupleScope `json:"scope"`

	// VPCID is required when Scope=VPC and ignored otherwise.
	// +optional
	// +kubebuilder:validation:Minimum=0
	VPCID uint32 `json:"vpcID,omitempty"`

	// SrcIP is the source IPv4 address.
	// +required
	// +kubebuilder:validation:MinLength=1
	SrcIP string `json:"srcIP"`

	// DstIP is the destination IPv4 address.
	// +required
	// +kubebuilder:validation:MinLength=1
	DstIP string `json:"dstIP"`

	// SrcPort is the source L4 port. 0 wildcards the source port.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	SrcPort int32 `json:"srcPort,omitempty"`

	// DstPort is the destination L4 port. 0 wildcards the
	// destination port (e.g. ICMP sessions).
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	DstPort int32 `json:"dstPort,omitempty"`

	// Protocol selects the IP protocol matched by this tuple.
	// +required
	Protocol TraceProtocol `json:"protocol"`

	// Direction labels this tuple's leg. Defaults to Request. kubectl
	// sets Reply on the return-direction mirror it precomputes for each
	// Request tuple. Daemons program the value into trace_tuple_map so
	// every emitted event carries an authoritative request/reply tag.
	// +optional
	// +kubebuilder:default=Request
	Direction TraceTupleDirection `json:"direction,omitempty"`
}

// TraceSessionSpec is the desired state of a trace session.
type TraceSessionSpec struct {
	// TraceID is a session-stable identifier programmed into BPF
	// maps. Daemons use it to attach trace state to in-flight
	// packets without re-keying by full tuple. kubectl picks a
	// random non-zero value at session creation; uniqueness is the
	// caller's responsibility (collisions cause cross-talk between
	// concurrent sessions).
	// +required
	// +kubebuilder:validation:Minimum=1
	TraceID uint32 `json:"traceID"`

	// ExpiresAt is the wall-clock time after which daemons must
	// stop emitting events for this session and remove their local
	// dataplane state. Mandatory. Protects against orphan sessions
	// when kubectl crashes mid-trace. Daemons evaluate expiry on
	// every reconcile; kubectl typically sets ExpiresAt to now() +
	// session timeout + a small grace window.
	// +required
	ExpiresAt metav1.Time `json:"expiresAt"`

	// Mode selects ActiveProbe (probe injection) or ObserveOnly
	// (passive observation). ObserveOnly is the safe default for
	// production.
	// +required
	Mode TraceMode `json:"mode"`

	// Capture controls per-event detail and event-class selection.
	// +optional
	Capture TraceCaptureConfig `json:"capture,omitempty"`

	// Source identifies the originating endpoint. Used by kubectl
	// when computing initial tuples and shown in the rendered
	// timeline; daemons themselves match by tuple, not by source.
	// +required
	Source TraceEndpoint `json:"source"`

	// Destination identifies the target endpoint. Same role as
	// Source — kubectl uses it for tuple computation; daemons
	// match by tuple.
	// +required
	Destination TraceEndpoint `json:"destination"`

	// InitialTuples is the precomputed list of tuples kubectl
	// expects the dataplane to match. There can be more than one
	// per session because a Service ClusterIP may resolve to
	// multiple backend Pods (one tuple per backend), or because
	// kubectl wants to trace both directions of a flow at session
	// start. Additional tuples discovered post-NAT are learned by
	// daemons and fanned out via the debug stream.
	// +optional
	InitialTuples []TraceTuple `json:"initialTuples,omitempty"`
}

// TraceSessionPhase reflects the controller-perceived state of the
// session. Daemons do not write Phase; they only append to
// ObservedNodes and bump LastObservedAt.
//
// +kubebuilder:validation:Enum=Pending;Active;Expired;Terminating
type TraceSessionPhase string

const (
	// TraceSessionPhasePending is the initial phase: the CRD has
	// been created but no daemon has reported observation yet.
	TraceSessionPhasePending TraceSessionPhase = "Pending"
	// TraceSessionPhaseActive means at least one daemon has
	// programmed local trace maps and is emitting events.
	TraceSessionPhaseActive TraceSessionPhase = "Active"
	// TraceSessionPhaseExpired means the session passed
	// spec.expiresAt. Daemons stop emitting; kubectl may delete
	// the CRD.
	TraceSessionPhaseExpired TraceSessionPhase = "Expired"
	// TraceSessionPhaseTerminating signals that kubectl has
	// requested cleanup and daemons are removing local state.
	TraceSessionPhaseTerminating TraceSessionPhase = "Terminating"
)

// TraceSessionStatus is observed state.
type TraceSessionStatus struct {
	// Phase summarizes the lifecycle stage. Useful for kubectl
	// progress display; reconciliation does not branch on it.
	// +optional
	Phase TraceSessionPhase `json:"phase,omitempty"`

	// ObservedNodes lists the node names whose juneaud has
	// programmed local trace maps for this session. Updated by
	// the daemon-side reconciler. Order is not significant.
	// +optional
	ObservedNodes []string `json:"observedNodes,omitempty"`

	// LastObservedAt is the most recent time any daemon emitted a
	// trace event for this session. Surfaced to operators so a
	// "no events received" run is distinguishable from a daemon
	// outage.
	// +optional
	LastObservedAt *metav1.Time `json:"lastObservedAt,omitempty"`

	// Conditions reports detailed lifecycle signals. The defined
	// types live in the TraceSessionCondition* constants below.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	// TraceSessionConditionAccepted is True when every applicable
	// daemon has acknowledged the session and programmed BPF maps.
	TraceSessionConditionAccepted = "Accepted"
	// TraceSessionConditionExpired flips to True the first time a
	// daemon (or controller) notices the session has exceeded
	// spec.expiresAt.
	TraceSessionConditionExpired = "Expired"

	TraceSessionReasonProgramming = "Programming"
	TraceSessionReasonReady       = "Ready"
	TraceSessionReasonExpired     = "Expired"
	TraceSessionReasonTerminating = "Terminating"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName={"trace","traces"}
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.mode"
// +kubebuilder:printcolumn:name="TraceID",type="integer",JSONPath=".spec.traceID"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="ExpiresAt",type="date",JSONPath=".spec.expiresAt"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// TraceSession is the Schema for the tracesessions API.
type TraceSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TraceSessionSpec   `json:"spec,omitempty"`
	Status TraceSessionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TraceSessionList contains a list of TraceSession.
type TraceSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TraceSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TraceSession{}, &TraceSessionList{})
}
