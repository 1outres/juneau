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

// VpcSpec defines the desired state of Vpc.
type VpcSpec struct {
	// Service configures Service routing for this VPC. When nil, the
	// VPC has no Service routing — its Pods cannot reach any
	// ClusterIP and the controller does not inject a Service-typed
	// route into the VPC's main RouteTable.
	//
	// Two cross-VPC roles are independently configurable under this
	// field: Provider (this VPC hosts Services that other VPCs may
	// reach) and Consume (this VPC's Pods may reach shared Services
	// hosted in other VPCs). Setting either implicitly enables
	// Service routing for the VPC.
	// +optional
	Service *VpcServiceSpec `json:"service,omitempty"`

	// EnforceSecurityGroups makes SecurityGroup attachment mandatory for
	// every Pod placed in a Subnet of this Vpc. Pods without the
	// juneau.loutres.me/security-groups annotation (or with a list that
	// resolves to zero valid SGs) are rejected at admission. Existing
	// Pods are not retroactively affected when this flag is toggled.
	// +optional
	EnforceSecurityGroups bool `json:"enforceSecurityGroups,omitempty"`

	// EndpointPool declares the address space that VpcEndpoint VIPs are
	// allocated from. The CIDRs must fall outside every Subnet of this
	// Vpc: a VIP outside the Subnet is reached through the Vpc's
	// gateway, so it needs no arp_table entry and consumes no Pod
	// address.
	// +optional
	EndpointPool *VpcEndpointPoolSpec `json:"endpointPool,omitempty"`
}

// VpcEndpointPoolSpec configures the address space VpcEndpoint VIPs
// are drawn from. Several CIDRs are allowed so the pool can be grown
// later without disturbing addresses already handed out.
type VpcEndpointPoolSpec struct {
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	CIDRs []string `json:"cidrs"`
}

// VpcServiceSpec configures the Service-routing behaviour of a VPC,
// including its participation in cross-VPC shared Services.
//
// Setting either Provider or Consume enables Service routing for this
// VPC: the controller injects a Service-typed route into every
// RouteTable belonging to it so that Pods can reach ClusterIPs.
type VpcServiceSpec struct {
	// Provider, when set, makes Services in this VPC eligible to be
	// marked as cross-VPC shared via the
	// juneau.loutres.me/shared-service annotation. Per-Node SNAT IPs
	// are allocated from the configured Subnet so that backend
	// replies flow over this VPC's fabric back to the originating
	// caller's Node.
	// +optional
	Provider *VpcServiceProviderSpec `json:"provider,omitempty"`

	// Consume, when true, allows Pods in this VPC to call shared
	// Services hosted in other VPCs. The per-Service ACL annotation
	// (juneau.loutres.me/shared-service-allowed-consumer-vpcs) may
	// further restrict which provider Services this VPC can reach.
	// +optional
	Consume bool `json:"consume,omitempty"`
}

// VpcServiceProviderSpec configures the cross-VPC provider role of a VPC.
type VpcServiceProviderSpec struct {
	// NATSourceSubnet names a Subnet in this VPC from which per-Node
	// SNAT source IPs are allocated for cross-VPC callers reaching
	// shared Services owned by this VPC. The Subnet must exist and
	// belong to this VPC. Required to mark Services in this VPC as
	// shared.
	// +kubebuilder:validation:MinLength=1
	NATSourceSubnet string `json:"natSourceSubnet"`
}

// VpcStatus defines the observed state of Vpc.
type VpcStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	MainRouteTable string `json:"mainRouteTable,omitempty"`
	VpcID          uint32 `json:"vpcID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// Vpc is the Schema for the vpcs API.
type Vpc struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VpcSpec   `json:"spec,omitempty"`
	Status VpcStatus `json:"status,omitempty"`
}

const (
	VpcStatusReady string = "Ready"
)

// ServiceEnabled reports whether Service routing is enabled in this
// VPC. The VPC has Service routing iff at least one of the cross-VPC
// roles (Provider or Consume) is configured.
func (s *VpcSpec) ServiceEnabled() bool {
	if s == nil || s.Service == nil {
		return false
	}
	return s.Service.Consume || s.Service.IsProvider()
}

// IsProvider reports whether this Service spec opts the VPC in to the
// cross-VPC provider role (NATSourceSubnet configured).
func (s *VpcServiceSpec) IsProvider() bool {
	return s != nil && s.Provider != nil && s.Provider.NATSourceSubnet != ""
}

// ProviderSubnet returns the configured provider NAT source Subnet
// name, or empty when this VPC does not act as a provider.
func (s *VpcServiceSpec) ProviderSubnet() string {
	if s == nil || s.Provider == nil {
		return ""
	}
	return s.Provider.NATSourceSubnet
}

// Consumes reports whether this VPC opts in to consuming shared
// Services from other VPCs.
func (s *VpcServiceSpec) Consumes() bool {
	return s != nil && s.Consume
}

// Configured reports whether this VPC declares an endpoint pool that
// VpcEndpoint VIPs can be allocated from.
func (s *VpcEndpointPoolSpec) Configured() bool {
	return s != nil && len(s.CIDRs) > 0
}

// Cidrs returns the endpoint pool CIDRs, or nil when the pool is not
// configured.
func (s *VpcEndpointPoolSpec) Cidrs() []string {
	if !s.Configured() {
		return nil
	}
	return s.CIDRs
}

// +kubebuilder:object:root=true

// VpcList contains a list of Vpc.
type VpcList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Vpc `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Vpc{}, &VpcList{})
}
