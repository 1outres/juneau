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

import "testing"

func networkACLPorts(n int) []NetworkACLPort {
	ports := make([]NetworkACLPort, 0, n)
	for i := 0; i < n; i++ {
		port := int32(1000 + i)
		ports = append(ports, NetworkACLPort{Port: &port})
	}
	return ports
}

func securityGroupPorts(n int) []SecurityGroupPort {
	ports := make([]SecurityGroupPort, 0, n)
	for i := 0; i < n; i++ {
		port := int32(1000 + i)
		ports = append(ports, SecurityGroupPort{Port: &port})
	}
	return ports
}

func securityGroupPeers(n int) []SecurityGroupPeer {
	peers := make([]SecurityGroupPeer, 0, n)
	for i := 0; i < n; i++ {
		peers = append(peers, SecurityGroupPeer{CIDR: "10.0.0.0/8"})
	}
	return peers
}

func TestNetworkACLRuleEntryCount(t *testing.T) {
	tests := []struct {
		name string
		rule NetworkACLRule
		want int
	}{
		{"no ports", NetworkACLRule{}, 1},
		{"nil ports", NetworkACLRule{Ports: nil}, 1},
		{"empty ports", NetworkACLRule{Ports: []NetworkACLPort{}}, 1},
		{"one port", NetworkACLRule{Ports: networkACLPorts(1)}, 1},
		{"three ports", NetworkACLRule{Ports: networkACLPorts(3)}, 3},
		{"ports at the direction limit", NetworkACLRule{Ports: networkACLPorts(NetworkACLMaxEntriesPerDirection)}, NetworkACLMaxEntriesPerDirection},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NetworkACLRuleEntryCount(tt.rule); got != tt.want {
				t.Errorf("NetworkACLRuleEntryCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNetworkACLDirectionEntryCount(t *testing.T) {
	tests := []struct {
		name  string
		rules []NetworkACLRule
		want  int
	}{
		{"nil rules", nil, 0},
		{"empty rules", []NetworkACLRule{}, 0},
		{"single portless rule", []NetworkACLRule{{}}, 1},
		{
			"mixed rules",
			[]NetworkACLRule{
				{Ports: networkACLPorts(4)},
				{},
				{Ports: networkACLPorts(2)},
			},
			7,
		},
		{
			"direction exactly at the limit",
			[]NetworkACLRule{
				{Ports: networkACLPorts(10)},
				{Ports: networkACLPorts(6)},
			},
			NetworkACLMaxEntriesPerDirection,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NetworkACLDirectionEntryCount(tt.rules); got != tt.want {
				t.Errorf("NetworkACLDirectionEntryCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSecurityGroupIngressRuleEntryCount(t *testing.T) {
	tests := []struct {
		name string
		rule SecurityGroupIngressRule
		want int
	}{
		{"no peers and no ports", SecurityGroupIngressRule{}, 1},
		{"empty peers and empty ports", SecurityGroupIngressRule{From: []SecurityGroupPeer{}, Ports: []SecurityGroupPort{}}, 1},
		{"one peer, no ports", SecurityGroupIngressRule{From: securityGroupPeers(1)}, 1},
		{"three peers, no ports", SecurityGroupIngressRule{From: securityGroupPeers(3)}, 3},
		{"no peers, three ports", SecurityGroupIngressRule{Ports: securityGroupPorts(3)}, 3},
		{
			"three peers, two ports",
			SecurityGroupIngressRule{From: securityGroupPeers(3), Ports: securityGroupPorts(2)},
			6,
		},
		{
			"rule at the direction limit",
			SecurityGroupIngressRule{From: securityGroupPeers(4), Ports: securityGroupPorts(2)},
			SecurityGroupMaxEntriesPerDirection,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecurityGroupIngressRuleEntryCount(tt.rule); got != tt.want {
				t.Errorf("SecurityGroupIngressRuleEntryCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSecurityGroupEgressRuleEntryCount(t *testing.T) {
	tests := []struct {
		name string
		rule SecurityGroupEgressRule
		want int
	}{
		{"no peers and no ports", SecurityGroupEgressRule{}, 1},
		{"empty peers and empty ports", SecurityGroupEgressRule{To: []SecurityGroupPeer{}, Ports: []SecurityGroupPort{}}, 1},
		{"one peer, no ports", SecurityGroupEgressRule{To: securityGroupPeers(1)}, 1},
		{"three peers, no ports", SecurityGroupEgressRule{To: securityGroupPeers(3)}, 3},
		{"no peers, three ports", SecurityGroupEgressRule{Ports: securityGroupPorts(3)}, 3},
		{
			"two peers, five ports",
			SecurityGroupEgressRule{To: securityGroupPeers(2), Ports: securityGroupPorts(5)},
			10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecurityGroupEgressRuleEntryCount(tt.rule); got != tt.want {
				t.Errorf("SecurityGroupEgressRuleEntryCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSecurityGroupIngressEntryCount(t *testing.T) {
	tests := []struct {
		name  string
		rules []SecurityGroupIngressRule
		want  int
	}{
		{"nil rules", nil, 0},
		{"empty rules", []SecurityGroupIngressRule{}, 0},
		{"single bare rule", []SecurityGroupIngressRule{{}}, 1},
		{
			"mixed rules",
			[]SecurityGroupIngressRule{
				{From: securityGroupPeers(2), Ports: securityGroupPorts(3)},
				{From: securityGroupPeers(1)},
				{Ports: securityGroupPorts(4)},
			},
			11,
		},
		{
			"direction exactly at the limit",
			[]SecurityGroupIngressRule{
				{From: securityGroupPeers(2), Ports: securityGroupPorts(3)},
				{From: securityGroupPeers(2)},
			},
			SecurityGroupMaxEntriesPerDirection,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecurityGroupIngressEntryCount(tt.rules); got != tt.want {
				t.Errorf("SecurityGroupIngressEntryCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSecurityGroupEgressEntryCount(t *testing.T) {
	tests := []struct {
		name  string
		rules []SecurityGroupEgressRule
		want  int
	}{
		{"nil rules", nil, 0},
		{"empty rules", []SecurityGroupEgressRule{}, 0},
		{"single bare rule", []SecurityGroupEgressRule{{}}, 1},
		{
			"mixed rules",
			[]SecurityGroupEgressRule{
				{To: securityGroupPeers(3), Ports: securityGroupPorts(2)},
				{To: securityGroupPeers(4)},
			},
			10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecurityGroupEgressEntryCount(tt.rules); got != tt.want {
				t.Errorf("SecurityGroupEgressEntryCount() = %d, want %d", got, tt.want)
			}
		})
	}
}
