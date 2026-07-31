package topology

import (
	corev1 "k8s.io/api/core/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// PodContext is the resolved view returned for `describe pod`. Pod
// itself is preserved in case the presenter wants more raw fields; the
// distilled bits live on Interfaces.
type PodContext struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	Pod        *corev1.Pod        `json:"pod,omitempty"`
	Interfaces []InterfaceContext `json:"interfaces,omitempty"`
}

// InterfaceContext is the chain reachable from a single
// NetworkInterface. Used both as a leaf inside PodContext and as a
// standalone result for `describe networkinterface`.
type InterfaceContext struct {
	NetworkInterface *juneauv1alpha1.NetworkInterface           `json:"networkInterface,omitempty"`
	Attachment       *juneauv1alpha1.NetworkInterfaceAttachment `json:"attachment,omitempty"`

	Subnet *juneauv1alpha1.Subnet `json:"subnet,omitempty"`
	Vpc    *juneauv1alpha1.Vpc    `json:"vpc,omitempty"`

	// RouteTable is the resolved RouteTable governing this
	// interface's Subnet — either the Subnet's spec.routeTable
	// override, or the Vpc's main RouteTable.
	RouteTable       *RouteTableSummary `json:"routeTable,omitempty"`
	RouteTableIsMain bool               `json:"routeTableIsMain,omitempty"`

	NetworkACL     *NetworkACLSummary     `json:"networkACL,omitempty"`
	SecurityGroups []SecurityGroupSummary `json:"securityGroups,omitempty"`
	ElasticIP      *ElasticIPSummary      `json:"elasticIP,omitempty"`
}

// VpcContext is the result returned for `describe vpc`.
type VpcContext struct {
	Name string `json:"name"`

	Vpc *juneauv1alpha1.Vpc `json:"vpc,omitempty"`

	Subnets        []juneauv1alpha1.Subnet `json:"subnets,omitempty"`
	RouteTables    []RouteTableSummary     `json:"routeTables,omitempty"`
	SecurityGroups []SecurityGroupSummary  `json:"securityGroups,omitempty"`
	NetworkACLs    []NetworkACLSummary     `json:"networkACLs,omitempty"`
	NATGateways    []NATGatewaySummary     `json:"natGateways,omitempty"`
}

// SubnetContext is the result returned for `describe subnet`.
type SubnetContext struct {
	Name string `json:"name"`

	Subnet *juneauv1alpha1.Subnet `json:"subnet,omitempty"`
	Vpc    *juneauv1alpha1.Vpc    `json:"vpc,omitempty"`

	RouteTable       *RouteTableSummary `json:"routeTable,omitempty"`
	RouteTableIsMain bool               `json:"routeTableIsMain,omitempty"`

	NetworkACL *NetworkACLSummary `json:"networkACL,omitempty"`
	Interfaces []InterfaceContext `json:"interfaces,omitempty"`
}

// ServiceContext is the result returned for `describe service`. It
// surfaces (a) which Vpc owns the Service per annotation, (b) whether
// it is shared, and (c) which backend Pods land in which Vpcs (so
// cross-Vpc misconfiguration is visible in the tree).
type ServiceContext struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	Service *corev1.Service     `json:"service,omitempty"`
	VpcName string              `json:"vpcName,omitempty"`
	Vpc     *juneauv1alpha1.Vpc `json:"vpc,omitempty"`
	Shared  bool                `json:"shared"`

	Backends []ServiceBackend `json:"backends,omitempty"`
}

// ServiceBackend is one (Pod IP, Pod, Vpc) tuple for a Service backend.
type ServiceBackend struct {
	Address      string `json:"address"`
	NodeName     string `json:"nodeName,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
	PodName      string `json:"podName,omitempty"`
	SubnetName   string `json:"subnetName,omitempty"`
	VpcName      string `json:"vpcName,omitempty"`

	// SameVpc is true when the backend's owning Vpc matches the
	// Service's owning Vpc (or the Service is shared and the backend
	// is in the default Vpc). Surfaces VPC-mismatch
	// misconfiguration without forcing the presenter to re-derive.
	SameVpc bool `json:"sameVpc"`
}

// RouteTableSummary mirrors RouteTable.status.routes for presenters,
// avoiding a leaky import of juneauv1alpha1.Route into the renderer.
type RouteTableSummary struct {
	Name   string         `json:"name"`
	IsMain bool           `json:"isMain,omitempty"`
	Routes []RouteSummary `json:"routes,omitempty"`
}

// RouteSummary is a flat copy of one Route entry. Type uses the same
// string values as juneauv1alpha1.RouteViaType.
type RouteSummary struct {
	Dst        string `json:"dst"`
	Type       string `json:"type"`
	Subnet     string `json:"subnet,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	NATGateway string `json:"natGateway,omitempty"`
}

// NetworkACLSummary mirrors the per-ACL fields a tree presenter needs.
// Keeps presenters from chasing pointers into juneauv1alpha1 status.
type NetworkACLSummary struct {
	Name            string `json:"name"`
	ACLID           uint32 `json:"aclID,omitempty"`
	IngressRules    int32  `json:"ingressRules,omitempty"`
	EgressRules     int32  `json:"egressRules,omitempty"`
	HasIngressRules bool   `json:"hasIngressRules,omitempty"`
	HasEgressRules  bool   `json:"hasEgressRules,omitempty"`
	RulesetVersion  uint64 `json:"rulesetVersion,omitempty"`
}

// SecurityGroupSummary mirrors the per-SG fields a tree presenter
// needs.
type SecurityGroupSummary struct {
	Name           string `json:"name"`
	GroupID        uint32 `json:"groupID,omitempty"`
	IngressRules   int32  `json:"ingressRules,omitempty"`
	EgressRules    int32  `json:"egressRules,omitempty"`
	HasEgressRules bool   `json:"hasEgressRules,omitempty"`
	RulesetVersion uint64 `json:"rulesetVersion,omitempty"`
}

// NATGatewaySummary mirrors NATGateway state for `describe vpc`.
type NATGatewaySummary struct {
	Name            string `json:"name"`
	GatewayID       uint32 `json:"gatewayID,omitempty"`
	ExternalNetwork string `json:"externalNetwork,omitempty"`
}

// ElasticIPSummary is the resolved attachment + EIP view for a single
// NetworkInterface.
type ElasticIPSummary struct {
	AttachmentName string                                  `json:"attachmentName"`
	ElasticIPName  string                                  `json:"elasticIPName,omitempty"`
	Address        string                                  `json:"address,omitempty"`
	Phase          juneauv1alpha1.ElasticIPAttachmentPhase `json:"phase,omitempty"`
}
