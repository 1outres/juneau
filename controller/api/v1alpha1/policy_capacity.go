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

// Policy capacity is measured in ENTRIES, not in rules.
//
// A rule the user writes is not what the data plane stores. The BPF rule
// tables hold flat entries that match one protocol against one port (or
// port range) for one peer, so the controller expands every rule into the
// cross-product of the lists it carries before writing it out:
//
//   - a NetworkACL rule carries one CIDR and a list of ports, so it
//     expands over its ports;
//   - a SecurityGroup rule carries a list of peers and a list of ports, so
//     it expands over both.
//
// An empty port list means "any port" and an empty peer list means "any
// peer". Neither disappears at expansion time: both still produce one
// entry. That is why every factor below is floored at 1 rather than
// summed as-is.
//
// Capacity is therefore a budget of entries, and it is a budget PER
// DIRECTION: ingress and egress own separate windows in the BPF rule
// table, so filling one direction can never starve the other.
//
// Counting lives here, in the API package, because four different
// components have to agree on it exactly: the webhook rejects a spec that
// does not fit, the controller reports the cost in status, the daemon
// installs the entries, and mNi-Cloud/vpc-controller sizes user-facing
// quotas against the same numbers. A component that counts rules instead
// of entries will accept specs the data plane cannot hold.

const (
	// NetworkACLMaxEntriesPerDirection is how many expanded entries one
	// direction of a NetworkACL may occupy. Raising it requires raising
	// MAX_ACL_RULES_PER_DIR in the daemon's maps.h to match.
	NetworkACLMaxEntriesPerDirection = 16

	// SecurityGroupMaxEntriesPerDirection is how many expanded entries one
	// direction of a SecurityGroup may occupy. It is half the NetworkACL
	// budget because a NetworkInterface attaches up to MAX_SGS_PER_NIC
	// SecurityGroups and the data plane scans every one of them, while a
	// Subnet carries exactly one NetworkACL. Raising it to 16 was measured
	// and pushes tc_pod_egress past the verifier 1M instruction ceiling,
	// so this is a hard limit rather than a chosen one.
	SecurityGroupMaxEntriesPerDirection = 8
)

// NetworkACLRuleEntryCount returns how many data plane entries one
// NetworkACL rule costs: one per port, or one when the rule lists no
// ports and therefore matches every port.
func NetworkACLRuleEntryCount(rule NetworkACLRule) int {
	return atLeastOne(len(rule.Ports))
}

// NetworkACLDirectionEntryCount returns the total data plane cost of one
// direction of a NetworkACL. Compare it against
// NetworkACLMaxEntriesPerDirection.
func NetworkACLDirectionEntryCount(rules []NetworkACLRule) int {
	return sumEntryCount(rules, NetworkACLRuleEntryCount)
}

// SecurityGroupIngressRuleEntryCount returns how many data plane entries
// one SecurityGroup ingress rule costs: one per (peer, port) pair, where
// an empty peer or port list still counts as one.
//
// The count is static: it uses the peers as written, before any
// SecurityGroupRef is resolved. Peers that resolve to nothing are dropped
// at expansion time, so the runtime cost is never higher than this.
func SecurityGroupIngressRuleEntryCount(rule SecurityGroupIngressRule) int {
	return securityGroupRuleEntryCount(len(rule.From), len(rule.Ports))
}

// SecurityGroupEgressRuleEntryCount returns how many data plane entries
// one SecurityGroup egress rule costs. See
// SecurityGroupIngressRuleEntryCount for the counting rule.
func SecurityGroupEgressRuleEntryCount(rule SecurityGroupEgressRule) int {
	return securityGroupRuleEntryCount(len(rule.To), len(rule.Ports))
}

// SecurityGroupIngressEntryCount returns the total data plane cost of a
// SecurityGroup's ingress rules. Compare it against
// SecurityGroupMaxEntriesPerDirection.
func SecurityGroupIngressEntryCount(rules []SecurityGroupIngressRule) int {
	return sumEntryCount(rules, SecurityGroupIngressRuleEntryCount)
}

// SecurityGroupEgressEntryCount returns the total data plane cost of a
// SecurityGroup's egress rules. Compare it against
// SecurityGroupMaxEntriesPerDirection.
func SecurityGroupEgressEntryCount(rules []SecurityGroupEgressRule) int {
	return sumEntryCount(rules, SecurityGroupEgressRuleEntryCount)
}

func securityGroupRuleEntryCount(peers, ports int) int {
	return atLeastOne(peers) * atLeastOne(ports)
}

func sumEntryCount[Rule any](rules []Rule, entryCount func(Rule) int) int {
	total := 0
	for _, rule := range rules {
		total += entryCount(rule)
	}
	return total
}

func atLeastOne(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
