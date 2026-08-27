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
	"k8s.io/apimachinery/pkg/util/intstr"
)

// SecurityGroupPeer expresses a single source/destination scope.
//
// Exactly one of CIDR or SecurityGroupRef must be set. Webhook validation
// enforces this invariant; the controller assumes it during expansion.
type SecurityGroupPeer struct {
	// CIDR matches any address inside the given IPv4 prefix.
	// Mutually exclusive with SecurityGroupRef.
	// +optional
	CIDR string `json:"cidr,omitempty"`

	// SecurityGroupRef matches any NetworkInterface whose membership set
	// includes the referenced SecurityGroup. The referenced SG must
	// belong to the same Vpc as this rule's parent.
	// Mutually exclusive with CIDR.
	// +optional
	SecurityGroupRef *SecurityGroupPeerRef `json:"securityGroupRef,omitempty"`
}

// SecurityGroupPeerRef names a peer SecurityGroup. The reference is
// resolved at admission time and re-resolved by the controller; rules that
// point at deleted SGs are dropped from the effective ruleset.
type SecurityGroupPeerRef struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// SecurityGroupPort selects an L4 destination port (or range).
//
// Either Port or PortRange must be set, never both. Webhook validation
// enforces this invariant.
type SecurityGroupPort struct {
	// Port matches a single L4 destination port.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`

	// PortRange matches a contiguous L4 destination port range.
	// +optional
	PortRange *SecurityGroupPortRange `json:"portRange,omitempty"`
}

// SecurityGroupPortRange specifies an inclusive [From,To] port range. To
// must be >= From.
type SecurityGroupPortRange struct {
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	From int32 `json:"from"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	To int32 `json:"to"`
}

// SecurityGroupIngressRule allows ingress traffic that matches the
// (peer × protocol × ports) cross-product. Multiple ingress rules are
// ORed together.
type SecurityGroupIngressRule struct {
	// From lists the peers (CIDRs or SecurityGroupRefs) whose traffic
	// is admitted by this rule. At least one peer is required.
	//
	// A rule costs peers × ports data plane entries, which no single
	// item cap can express. Each list is therefore capped at
	// SecurityGroupMaxEntriesPerDirection so neither factor alone can
	// overflow the direction, and the webhook checks the product; see
	// policy_capacity.go.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	From []SecurityGroupPeer `json:"from"`

	// Protocol selects the IP protocol this rule matches. Accepts a
	// keyword (all, icmp, tcp, udp, sctp, gre, esp, ah) or an integer
	// IP protocol number in [0, 255]. "all" matches every protocol.
	// Ports are only valid for tcp and udp.
	// +optional
	// +kubebuilder:default=all
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:XValidation:rule="type(self) == int ? (self >= 0 && self <= 255) : self in ['all', 'icmp', 'tcp', 'udp', 'sctp', 'gre', 'esp', 'ah']",message="protocol must be a keyword (all, icmp, tcp, udp, sctp, gre, esp, ah) or an integer IP protocol number in [0, 255]"
	Protocol *intstr.IntOrString `json:"protocol,omitempty"`

	// Ports list the destination ports admitted by this rule. Empty
	// list (or unset) matches any port for the chosen protocol. Ports
	// may only be set when Protocol is tcp or udp.
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Ports []SecurityGroupPort `json:"ports,omitempty"`

	// Description is free-form metadata returned in API responses for
	// operator clarity; ignored by the data plane.
	// +optional
	Description string `json:"description,omitempty"`
}

// SecurityGroupEgressRule mirrors SecurityGroupIngressRule but for
// egress. The "to" side semantics are identical to "from".
type SecurityGroupEgressRule struct {
	// To lists the peers (CIDRs or SecurityGroupRefs) admitted by this
	// rule. At least one peer is required.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	To []SecurityGroupPeer `json:"to"`

	// Protocol selects the IP protocol this rule matches. Accepts a
	// keyword (all, icmp, tcp, udp, sctp, gre, esp, ah) or an integer
	// IP protocol number in [0, 255]. "all" matches every protocol.
	// Ports are only valid for tcp and udp.
	// +optional
	// +kubebuilder:default=all
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:XValidation:rule="type(self) == int ? (self >= 0 && self <= 255) : self in ['all', 'icmp', 'tcp', 'udp', 'sctp', 'gre', 'esp', 'ah']",message="protocol must be a keyword (all, icmp, tcp, udp, sctp, gre, esp, ah) or an integer IP protocol number in [0, 255]"
	Protocol *intstr.IntOrString `json:"protocol,omitempty"`

	// Ports list the destination ports admitted by this rule. Ports
	// may only be set when Protocol is tcp or udp.
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Ports []SecurityGroupPort `json:"ports,omitempty"`

	// Description is free-form metadata.
	// +optional
	Description string `json:"description,omitempty"`
}

// SecurityGroupSpec defines the desired state of SecurityGroup.
//
// Semantics:
//
//   - A SecurityGroup is scoped to exactly one Vpc. Cross-Vpc references
//     are rejected by webhook validation.
//   - Ingress is implicitly deny-all; rules whitelist what is admitted.
//   - When Egress is nil (the field is omitted), egress is implicitly
//     allow-all (AWS-compatible default). When Egress is set (even as an
//     empty list), egress flips to deny-by-default + allow-list.
type SecurityGroupSpec struct {
	// Vpc names the Vpc this SecurityGroup belongs to. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`

	// Ingress lists rules permitting inbound traffic. Empty/omitted
	// means "deny all ingress".
	//
	// The item cap is SecurityGroupMaxEntriesPerDirection because every
	// rule costs at least one entry, so a longer list can never fit the
	// direction anyway. The webhook still checks the expanded cost; see
	// policy_capacity.go.
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Ingress []SecurityGroupIngressRule `json:"ingress,omitempty"`

	// Egress lists rules permitting outbound traffic. nil (the field
	// is omitted entirely) means "allow all egress" (AWS-compatible
	// default). A non-nil list (even empty) flips egress to
	// "deny-by-default, allow-by-rule".
	// +optional
	// +nullable
	// +kubebuilder:validation:MaxItems=8
	Egress *[]SecurityGroupEgressRule `json:"egress,omitempty"`
}

// SecurityGroupStatus reports observed state.
type SecurityGroupStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// GroupID is the cluster-wide identifier allocated for this
	// SecurityGroup via an AllocationClaim. Daemon and BPF maps
	// reference this number; once assigned it never changes for the
	// lifetime of the resource.
	GroupID uint32 `json:"groupID,omitempty"`

	// RulesetVersion is bumped every time the controller resolves a
	// new effective ruleset. Daemons can use it to detect and ack
	// rule changes.
	RulesetVersion uint64 `json:"rulesetVersion,omitempty"`

	// IngressRuleCount and EgressRuleCount report the rule count per
	// direction, exactly as the user wrote them in the spec.
	// Observability; not a hard limit.
	IngressRuleCount int32 `json:"ingressRuleCount,omitempty"`
	EgressRuleCount  int32 `json:"egressRuleCount,omitempty"`

	// IngressEntryCount and EgressEntryCount report what each direction
	// costs in the data plane, which is what capacity is actually
	// budgeted against: a rule expands to one entry per (peer, port)
	// pair. See SecurityGroupIngressEntryCount and
	// SecurityGroupMaxEntriesPerDirection.
	//
	// The counts are static, so they include peers whose
	// SecurityGroupRef no longer resolves; such peers are dropped at
	// expansion time and the installed entry count is then lower.
	IngressEntryCount int32 `json:"ingressEntryCount,omitempty"`
	EgressEntryCount  int32 `json:"egressEntryCount,omitempty"`

	// HasEgressRules mirrors the spec choice (nil → false). Daemons
	// use this to decide whether to apply egress allow-list semantics
	// or default-allow.
	HasEgressRules bool `json:"hasEgressRules,omitempty"`

	// AttachedInterfaces enumerates NetworkInterfaces currently
	// referencing this SecurityGroup. Updated by the controller from
	// an informer; it is observability-only and may lag briefly.
	AttachedInterfaces []SecurityGroupAttachedInterface `json:"attachedInterfaces,omitempty"`
}

// SecurityGroupAttachedInterface identifies a NetworkInterface that
// references this SecurityGroup.
type SecurityGroupAttachedInterface struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

const (
	// SecurityGroupConditionReady is set to True when the controller
	// has assigned a GroupID, validated all peer references, and
	// projected the ruleset summary into status.
	SecurityGroupConditionReady = "Ready"
	// SecurityGroupConditionRulesValid is set to True when every rule
	// expanded cleanly (peer references resolved, ports valid).
	SecurityGroupConditionRulesValid = "RulesValid"

	SecurityGroupReasonReconcileSucceeded = "ReconcileSucceeded"
	SecurityGroupReasonAllocating         = "Allocating"
	SecurityGroupReasonAllocationFailed   = "AllocationFailed"
	SecurityGroupReasonVpcNotFound        = "VpcNotFound"
	SecurityGroupReasonRulesInvalid       = "RulesInvalid"
	SecurityGroupReasonPeerNotFound       = "PeerNotFound"
	SecurityGroupReasonRuleLimitExceeded  = "RuleLimitExceeded"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName={"sg","secgroup"}
// +kubebuilder:printcolumn:name="VPC",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="GroupID",type="integer",JSONPath=".status.groupID"
// +kubebuilder:printcolumn:name="Ingress",type="integer",JSONPath=".status.ingressRuleCount"
// +kubebuilder:printcolumn:name="Egress",type="integer",JSONPath=".status.egressRuleCount"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// SecurityGroup is the Schema for the securitygroups API.
type SecurityGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityGroupSpec   `json:"spec,omitempty"`
	Status SecurityGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecurityGroupList contains a list of SecurityGroup.
type SecurityGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityGroup{}, &SecurityGroupList{})
}
