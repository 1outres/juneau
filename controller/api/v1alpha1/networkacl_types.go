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

// NetworkACLProtocol selects which IP protocol a rule matches.
//
// "all" is a wildcard that suppresses any L4 port match (ports list must be
// empty). icmp accepts only protocol-level matching; ICMP type/code is not
// expressed by NetworkACL rules in v1alpha1.
//
// "all" means tcp, udp and icmp, and nothing else. No rule can name SCTP,
// GRE, ESP or any other IP protocol, so the data plane drops packets that
// use one at the Pod NIC. It drops them even when the Subnet has no
// NetworkACL and the Pod has no SecurityGroup.
//
// The values intentionally line up with SecurityGroupProtocol so the same
// BPF matching primitives (policy_match.h) handle both layers. The Go
// types are kept separate so mixing an SG rule with an ACL rule fails at
// compile time rather than at the BPF write path.
//
// +kubebuilder:validation:Enum=tcp;udp;icmp;all
type NetworkACLProtocol string

const (
	NetworkACLProtocolTCP  NetworkACLProtocol = "tcp"
	NetworkACLProtocolUDP  NetworkACLProtocol = "udp"
	NetworkACLProtocolICMP NetworkACLProtocol = "icmp"
	NetworkACLProtocolAll  NetworkACLProtocol = "all"
)

// NetworkACLAction is the verdict of a matching rule.
//
// Rules are evaluated in priority order; the first matching rule's action
// is final. When no rule matches, the direction's default applies (see
// NetworkACLSpec for the nil-vs-[] convention).
//
// +kubebuilder:validation:Enum=allow;deny
type NetworkACLAction string

const (
	// NetworkACLActionAllow admits the matching packet to the next
	// policy layer (SecurityGroup) for further evaluation.
	NetworkACLActionAllow NetworkACLAction = "allow"
	// NetworkACLActionDeny drops the matching packet immediately;
	// neither SecurityGroup nor any downstream stage sees it.
	NetworkACLActionDeny NetworkACLAction = "deny"
)

// NetworkACLPort selects an L4 destination port (or range).
//
// Either Port or PortRange must be set, never both. Webhook validation
// enforces this invariant. The struct mirrors SecurityGroupPort but is
// kept distinct so an accidental cross-kind assignment fails to compile.
type NetworkACLPort struct {
	// Port matches a single L4 destination port.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`

	// PortRange matches a contiguous L4 destination port range.
	// +optional
	PortRange *NetworkACLPortRange `json:"portRange,omitempty"`
}

// NetworkACLPortRange specifies an inclusive [From,To] port range. To
// must be >= From.
type NetworkACLPortRange struct {
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	From int32 `json:"from"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	To int32 `json:"to"`
}

// NetworkACLRule is a single ordered rule applied at the Subnet
// boundary.
//
// Unlike SecurityGroup, NetworkACL rules carry an explicit Priority and
// Action: rules run in priority order (low number first) and the first
// match decides the verdict. Peers are CIDR-only — Subnet-level ACLs
// describe address-based scopes; per-Pod identity matching belongs to
// SecurityGroup, which sits one stage downstream.
type NetworkACLRule struct {
	// Priority orders rules within their direction. Lower numbers run
	// first; the first matching rule's Action wins. Priorities must be
	// unique within each direction (webhook-enforced).
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Priority int32 `json:"priority"`

	// Action declares what to do when this rule matches.
	// +required
	Action NetworkACLAction `json:"action"`

	// Protocol selects the IP protocol. Defaults to "all" when empty.
	// "all" means tcp, udp and icmp; traffic using any other IP
	// protocol is dropped and no rule can admit it.
	// +optional
	// +kubebuilder:default=all
	Protocol NetworkACLProtocol `json:"protocol,omitempty"`

	// CIDR is the peer address scope this rule matches. IPv4 only.
	// "0.0.0.0/0" matches any address.
	// +required
	// +kubebuilder:validation:MinLength=1
	CIDR string `json:"cidr"`

	// Ports list the L4 destination ports admitted by this rule. Empty
	// matches every port for the chosen protocol. When Protocol is
	// "icmp" or "all", Ports must be empty.
	//
	// The item cap matches NetworkACLMaxEntriesPerDirection because a
	// rule costs one data plane entry per port: a single rule may fill
	// its direction but can never overflow it on its own.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Ports []NetworkACLPort `json:"ports,omitempty"`

	// Description is free-form metadata returned in API responses for
	// operator clarity; ignored by the data plane.
	// +optional
	Description string `json:"description,omitempty"`
}

// NetworkACLSpec defines the desired state of NetworkACL.
//
// Semantics:
//
//   - A NetworkACL is scoped to exactly one Vpc. Cross-Vpc references
//     are rejected by webhook validation.
//   - Each direction (Ingress, Egress) is independently configured:
//   - nil (the field is omitted entirely) → default-allow for that
//     direction. The Subnet boundary applies no policy and packets
//     fall through to SecurityGroup unchanged.
//   - non-nil empty list ([]) → default-deny. With no rules to match,
//     every packet hits the implicit terminal deny.
//   - non-empty list → rules evaluated in priority order; the first
//     match's Action wins. Packets that match no rule fall to the
//     implicit terminal deny.
//   - The nil-vs-[] convention mirrors SecurityGroup so operators can
//     reason about both layers consistently.
//   - A Subnet attaches at most one NetworkACL via Subnet.spec.networkACL.
//     Use rule priorities to compose multiple intents inside a single
//     ACL rather than chaining several ACLs onto one Subnet.
type NetworkACLSpec struct {
	// Vpc names the Vpc this NetworkACL belongs to. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`

	// Ingress lists rules controlling traffic entering Subnets that
	// reference this ACL. Per-direction defaults follow the
	// NetworkACLSpec nil-vs-[] convention.
	// +optional
	// +nullable
	Ingress *[]NetworkACLRule `json:"ingress,omitempty"`

	// Egress lists rules controlling traffic leaving Subnets that
	// reference this ACL.
	// +optional
	// +nullable
	Egress *[]NetworkACLRule `json:"egress,omitempty"`
}

// NetworkACLStatus reports observed state.
type NetworkACLStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// ACLID is the cluster-wide identifier allocated for this ACL via
	// an AllocationClaim. Daemons key acl_meta_map and acl_rule_table
	// by this number; once assigned it never changes for the lifetime
	// of the resource.
	ACLID uint32 `json:"aclID,omitempty"`

	// RulesetVersion is bumped whenever the controller publishes a new
	// effective ruleset summary. Daemons use this to invalidate stale
	// CT entries when rules change.
	RulesetVersion uint64 `json:"rulesetVersion,omitempty"`

	// IngressRuleCount and EgressRuleCount report the rule count per
	// direction (0 when the direction is nil/empty), exactly as the
	// user wrote them in the spec. Observability; not a hard limit.
	IngressRuleCount int32 `json:"ingressRuleCount,omitempty"`
	EgressRuleCount  int32 `json:"egressRuleCount,omitempty"`

	// IngressEntryCount and EgressEntryCount report what each direction
	// costs in the data plane, which is what capacity is actually
	// budgeted against: a rule expands to one entry per port. See
	// NetworkACLDirectionEntryCount and
	// NetworkACLMaxEntriesPerDirection.
	IngressEntryCount int32 `json:"ingressEntryCount,omitempty"`
	EgressEntryCount  int32 `json:"egressEntryCount,omitempty"`

	// HasIngressRules / HasEgressRules report whether the spec set the
	// direction explicitly (nil → false, [] or non-empty → true).
	// Daemons use these to choose between default-allow (no
	// enforcement at all) and default-deny (rule list applies, fall
	// through to deny).
	HasIngressRules bool `json:"hasIngressRules,omitempty"`
	HasEgressRules  bool `json:"hasEgressRules,omitempty"`

	// AttachedSubnets enumerates Subnets currently referencing this
	// NetworkACL via spec.networkACL. Updated by the controller from
	// an informer; observability only and may lag briefly.
	AttachedSubnets []string `json:"attachedSubnets,omitempty"`
}

const (
	// NetworkACLConditionReady is True when the controller has
	// allocated an ACLID, validated the spec, and projected status.
	NetworkACLConditionReady = "Ready"
	// NetworkACLConditionRulesValid is True when every rule passed
	// post-admission validation (no peer references to resolve here —
	// ACL rules carry CIDR only, so the condition is currently a
	// shape/limit check).
	NetworkACLConditionRulesValid = "RulesValid"

	NetworkACLReasonReconcileSucceeded = "ReconcileSucceeded"
	NetworkACLReasonAllocating         = "Allocating"
	NetworkACLReasonAllocationFailed   = "AllocationFailed"
	NetworkACLReasonVpcNotFound        = "VpcNotFound"
	NetworkACLReasonRulesInvalid       = "RulesInvalid"
	NetworkACLReasonRuleLimitExceeded  = "RuleLimitExceeded"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName={"netacl"}
// +kubebuilder:printcolumn:name="VPC",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="ACLID",type="integer",JSONPath=".status.aclID"
// +kubebuilder:printcolumn:name="Ingress",type="integer",JSONPath=".status.ingressRuleCount"
// +kubebuilder:printcolumn:name="Egress",type="integer",JSONPath=".status.egressRuleCount"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// NetworkACL is the Schema for the networkacls API.
type NetworkACL struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkACLSpec   `json:"spec,omitempty"`
	Status NetworkACLStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkACLList contains a list of NetworkACL.
type NetworkACLList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkACL `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkACL{}, &NetworkACLList{})
}
