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

// TransitGatewayAttachmentSpec defines the desired state of
// TransitGatewayAttachment.
//
// AWS models association and propagation as their own API objects. An
// attachment has exactly one association and any number of
// propagations, so both fit naturally into the attachment spec and
// Kubernetes users get one object to reason about instead of three.
type TransitGatewayAttachmentSpec struct {
	// TransitGateway names the TransitGateway this attachment connects
	// to. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	TransitGateway string `json:"transitGateway"`

	// Vpc names the Vpc this attachment connects. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`

	// Association names the TransitGatewayRouteTable that traffic
	// arriving from this attachment is looked up in.
	// +required
	// +kubebuilder:validation:MinLength=1
	Association string `json:"association"`

	// Propagations lists the TransitGatewayRouteTables this
	// attachment's Vpc prefixes are advertised into.
	// +optional
	Propagations []string `json:"propagations,omitempty"`
}

// TransitGatewayAttachmentStatus defines the observed state of
// TransitGatewayAttachment.
type TransitGatewayAttachmentStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`

	// Prefixes enumerates the Subnets this attachment advertises into
	// the route tables listed in spec.propagations. Sorted by cidr.
	Prefixes []TransitGatewayAttachmentPrefix `json:"prefixes,omitempty"`
}

// TransitGatewayAttachmentPrefix is one Subnet of the attached Vpc.
type TransitGatewayAttachmentPrefix struct {
	CIDR   string `json:"cidr"`
	Subnet string `json:"subnet"`
}

const (
	TransitGatewayAttachmentStatusReady string = "Ready"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="TransitGateway",type="string",JSONPath=".spec.transitGateway"
// +kubebuilder:printcolumn:name="Vpc",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="Association",type="string",JSONPath=".spec.association"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"

// TransitGatewayAttachment is the Schema for the
// transitgatewayattachments API.
type TransitGatewayAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TransitGatewayAttachmentSpec   `json:"spec,omitempty"`
	Status TransitGatewayAttachmentStatus `json:"status,omitempty"`
}

// RouteTables returns every TransitGatewayRouteTable this attachment
// references, association first and then the propagations, with
// duplicates removed.
func (s *TransitGatewayAttachmentSpec) RouteTables() []string {
	tables := make([]string, 0, 1+len(s.Propagations))
	seen := make(map[string]struct{}, 1+len(s.Propagations))
	for _, name := range append([]string{s.Association}, s.Propagations...) {
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		tables = append(tables, name)
	}
	return tables
}

// PropagatesInto reports whether this attachment advertises its Vpc
// prefixes into the named TransitGatewayRouteTable.
func (s *TransitGatewayAttachmentSpec) PropagatesInto(routeTable string) bool {
	for _, name := range s.Propagations {
		if name == routeTable {
			return true
		}
	}
	return false
}

// +kubebuilder:object:root=true

// TransitGatewayAttachmentList contains a list of
// TransitGatewayAttachment.
type TransitGatewayAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransitGatewayAttachment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TransitGatewayAttachment{}, &TransitGatewayAttachmentList{})
}
