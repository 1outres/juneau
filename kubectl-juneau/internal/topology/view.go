package topology

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// View is the read-only abstraction the resolver functions speak. It
// is split between corev1 / discoveryv1 reads (for Services, Pods,
// EndpointSlices) and Juneau CRD reads.
//
// The contract for every method is "return (nil, nil) when the named
// object does not exist". Callers can then render `(not found)`
// branches without distinguishing IsNotFound from a real failure on
// every call site.
//
// Implementations are expected to memoise: a single command run will
// often resolve the same Vpc multiple times (once per Subnet in the
// Vpc, once for the owning Pod's Subnet, …) and we do not want to pay
// O(N) round-trips for that.
type View interface {
	// ---- corev1 / discoveryv1 ----------------------------------

	Pod(ctx context.Context, ns, name string) (*corev1.Pod, error)
	Service(ctx context.Context, ns, name string) (*corev1.Service, error)
	EndpointSlicesForService(ctx context.Context, ns, name string) ([]discoveryv1.EndpointSlice, error)

	// ---- Juneau v1alpha1 — single object -----------------------

	Vpc(ctx context.Context, name string) (*juneauv1alpha1.Vpc, error)
	Subnet(ctx context.Context, name string) (*juneauv1alpha1.Subnet, error)
	RouteTable(ctx context.Context, name string) (*juneauv1alpha1.RouteTable, error)
	NetworkInterface(ctx context.Context, ns, name string) (*juneauv1alpha1.NetworkInterface, error)
	NetworkInterfaceAttachment(ctx context.Context, ns, name string) (*juneauv1alpha1.NetworkInterfaceAttachment, error)
	SecurityGroup(ctx context.Context, name string) (*juneauv1alpha1.SecurityGroup, error)
	NetworkACL(ctx context.Context, name string) (*juneauv1alpha1.NetworkACL, error)
	NATGateway(ctx context.Context, name string) (*juneauv1alpha1.NATGateway, error)

	// ---- Juneau v1alpha1 — listings ----------------------------

	SubnetsByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.Subnet, error)
	RouteTablesByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.RouteTable, error)
	SecurityGroupsByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.SecurityGroup, error)
	NetworkACLsByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.NetworkACL, error)
	NATGatewaysByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.NATGateway, error)

	NetworkInterfacesByPod(ctx context.Context, ns, name, uid string) ([]juneauv1alpha1.NetworkInterface, error)
	NetworkInterfacesBySubnet(ctx context.Context, subnet string) ([]juneauv1alpha1.NetworkInterface, error)

	ElasticIPAttachmentsForNIC(ctx context.Context, nicName string) ([]juneauv1alpha1.ElasticIPAttachment, error)
	ElasticIP(ctx context.Context, name string) (*juneauv1alpha1.ElasticIP, error)

	// ServiceLoadBalancer returns the SLB resource that fronts a
	// Juneau-managed LoadBalancer Service. The SLB name is the same
	// as the Service name in the same namespace; this method exists
	// so resolvers don't have to re-derive that.
	ServiceLoadBalancer(ctx context.Context, ns, name string) (*juneauv1alpha1.ServiceLoadBalancer, error)

	// ExternalNetwork returns a cluster-scoped ExternalNetwork
	// resource, used to surface its type (bgp/arp) and pool list.
	ExternalNetwork(ctx context.Context, name string) (*juneauv1alpha1.ExternalNetwork, error)
}
