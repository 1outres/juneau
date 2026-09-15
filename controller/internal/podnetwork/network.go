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

// Package podnetwork resolves "the network a Pod NIC joins" to one view,
// no matter whether a Subnet, an L2Network or an ElasticIP backs it. The
// controllers and the admission webhooks both build on that view instead
// of reading each kind on their own.
package podnetwork

import (
	"context"
	"fmt"
	"net/netip"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/addressrange"
)

const (
	// subnetIPAllocationPoolPrefix prefixes the auto-generated
	// AllocationPool that backs Pod addresses on a Subnet. Distinct from
	// the AddressPool-derived ("addr-…") namespace so the two never
	// collide.
	subnetIPAllocationPoolPrefix = "subnet-ip-"

	// l2NetworkIPAllocationPoolPrefix does the same for an L2Network
	// that declares a CIDR.
	l2NetworkIPAllocationPoolPrefix = "l2network-ip-"
)

// Kind names the resource that backs a network.
type Kind string

const (
	KindSubnet    Kind = "Subnet"
	KindL2Network Kind = "L2Network"
	KindElasticIP Kind = "ElasticIP"
)

// SubnetAllocationPoolName returns the AllocationPool that backs
// addresses on the named Subnet.
func SubnetAllocationPoolName(name string) string {
	return subnetIPAllocationPoolPrefix + name
}

// L2NetworkAllocationPoolName returns the AllocationPool that backs
// addresses on the named L2Network. An L2Network without a CIDR never
// gets one.
func L2NetworkAllocationPoolName(name string) string {
	return l2NetworkIPAllocationPoolPrefix + name
}

// Reference names the network something joins. Exactly one of Subnet,
// L2Network and ElasticIP is set; none and more than one are errors the
// API schema rejects.
type Reference struct {
	Subnet    string
	L2Network string

	// ElasticIP names an ElasticIP in Namespace. A NIC that carries one
	// holds that address directly instead of joining a Vpc.
	ElasticIP string

	// Namespace is the namespace of the NIC. Subnets and L2Networks are
	// cluster-scoped and do not use it; an ElasticIP is looked up in it,
	// because a NIC can only carry an ElasticIP of its own namespace.
	Namespace string
}

// InterfaceReference reads the network a NetworkInterface joins.
func InterfaceReference(networkInterface *juneauv1alpha1.NetworkInterface) Reference {
	return Reference{
		Subnet:    networkInterface.Spec.Subnet,
		L2Network: networkInterface.Spec.L2Network,
		ElasticIP: networkInterface.Spec.ElasticIP,
		Namespace: networkInterface.Namespace,
	}
}

// AttachmentReference reads the network a Pod NIC annotation names, for a
// Pod in the given namespace.
func AttachmentReference(namespace string, attachment juneauv1alpha1.PodNetworkAttachment) Reference {
	return Reference{
		Subnet:    attachment.Subnet,
		L2Network: attachment.L2Network,
		ElasticIP: attachment.ElasticIP,
		Namespace: namespace,
	}
}

// Kind reports which resource the reference names. It is only
// meaningful once Validate has passed.
func (r Reference) Kind() Kind {
	switch {
	case r.ElasticIP != "":
		return KindElasticIP
	case r.L2Network != "":
		return KindL2Network
	default:
		return KindSubnet
	}
}

// Name is the object name the reference points at.
func (r Reference) Name() string {
	switch r.Kind() {
	case KindElasticIP:
		return r.ElasticIP
	case KindL2Network:
		return r.L2Network
	default:
		return r.Subnet
	}
}

// String renders the reference for messages, e.g. `Subnet "web"` or
// `ElasticIP "shop/web"`.
func (r Reference) String() string {
	if r.Kind() == KindElasticIP {
		return fmt.Sprintf("%s %q", r.Kind(), r.Namespace+"/"+r.ElasticIP)
	}
	return fmt.Sprintf("%s %q", r.Kind(), r.Name())
}

// HasAllocationPool reports whether the referenced kind of network hands
// addresses out of an AllocationPool. A Subnet and an L2Network do; an
// L2Network without a CIDR counts too, because telling it apart needs the
// object. An ElasticIP never does: it owns its one address.
func (r Reference) HasAllocationPool() bool {
	return r.Kind() != KindElasticIP
}

// AllocationPoolName is the AllocationPool that backs addresses on the
// referenced network. Reading it needs no cluster access, so a caller
// can find the pool of a network that has already been deleted.
//
// It is only meaningful when HasAllocationPool is true; for an ElasticIP
// the empty string comes back.
func (r Reference) AllocationPoolName() string {
	switch r.Kind() {
	case KindElasticIP:
		return ""
	case KindL2Network:
		return L2NetworkAllocationPoolName(r.L2Network)
	default:
		return SubnetAllocationPoolName(r.Subnet)
	}
}

// Validate reports whether the reference names exactly one network.
func (r Reference) Validate() error {
	named := 0
	for _, name := range []string{r.Subnet, r.L2Network, r.ElasticIP} {
		if name != "" {
			named++
		}
	}
	switch {
	case named == 0:
		return fmt.Errorf("none of a Subnet, an L2Network and an ElasticIP is named")
	case named > 1:
		return fmt.Errorf("more than one network is named: Subnet %q, L2Network %q, ElasticIP %q", r.Subnet, r.L2Network, r.ElasticIP)
	case r.ElasticIP != "" && r.Namespace == "":
		return fmt.Errorf("ElasticIP %q is named without the namespace to look it up in", r.ElasticIP)
	}
	return nil
}

// Network is the resolved view of the network a NIC joins. Callers
// program a NIC from this alone and never read the backing object.
type Network struct {
	// Reference is what named this network.
	Reference Reference

	// Vpc is the Vpc the network belongs to. Every SecurityGroup and
	// NetworkACL a NIC on it uses has to live in the same Vpc. Empty for
	// an ElasticIP, which joins no Vpc.
	Vpc string

	// CIDR is the prefix the network hands addresses out of. Empty for
	// an L2Network that declares none: NICs on it carry no address. Empty
	// for an ElasticIP too, which hands out nothing and owns one address.
	CIDR string

	// Gateway is the address a NIC on this network routes through.
	// Empty when the network has no gateway.
	Gateway string

	// HasGateway says whether the network declares a gateway at all.
	// It is read from the spec rather than from Gateway, which the
	// controller fills in a moment later: an admission check that waited
	// for status would reject a NIC created right after the network.
	HasGateway bool

	// ElasticIP is what a NIC that carries an ElasticIP holds. Nil for a
	// Subnet and an L2Network.
	ElasticIP *ElasticIPBinding
}

// ElasticIPBinding is the ElasticIP a NIC carries directly, read together
// with the ExternalNetwork its address belongs to.
type ElasticIPBinding struct {
	// Address is the address the ElasticIP holds. Empty until it has one.
	Address string

	// Attachment is what the ElasticIP controller says uses the address.
	// Only the NetworkInterface it names may carry the address.
	Attachment *juneauv1alpha1.ElasticIPStatusAttachment

	// ExternalNetwork names the ExternalNetwork of the ElasticIP.
	ExternalNetwork string

	// NetworkID is the network ID of that ExternalNetwork. Zero until it
	// has been given one.
	NetworkID uint32
}

// HeldBy reports whether the ElasticIP controller picked the named
// NetworkInterface to carry the address.
func (b ElasticIPBinding) HeldBy(networkInterface string) bool {
	return b.Attachment != nil &&
		b.Attachment.Kind == juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface &&
		b.Attachment.Name == networkInterface
}

// AllocatesAddresses reports whether the network hands out addresses.
func (n Network) AllocatesAddresses() bool {
	return n.CIDR != ""
}

// AllocationPoolName is the AllocationPool a NIC on this network claims
// its address from. Only meaningful when AllocatesAddresses is true.
func (n Network) AllocationPoolName() string {
	return n.Reference.AllocationPoolName()
}

// WaitingFor says what the network still lacks before a NIC can be built
// on it, or returns the empty string when nothing is missing. A Subnet
// and an L2Network are usable as soon as they exist. An ElasticIP needs
// its address and the network ID of its ExternalNetwork, because the data
// plane cannot carry the NIC without either.
func (n Network) WaitingFor() string {
	if n.ElasticIP == nil {
		return ""
	}
	switch {
	case n.ElasticIP.Address == "":
		return fmt.Sprintf("%s has no address yet", n.Reference)
	case n.ElasticIP.NetworkID == 0:
		return fmt.Sprintf("ExternalNetwork %q of %s has no network ID yet", n.ElasticIP.ExternalNetwork, n.Reference)
	}
	return ""
}

// Resolve reads the network a reference names. A reference that does
// not name exactly one network is an error, and a named object that
// does not exist comes back as the apierrors NotFound of that object so
// callers can keep telling "missing" apart from "broken". For an
// ElasticIP the same holds for its ExternalNetwork.
func Resolve(ctx context.Context, reader client.Reader, ref Reference) (*Network, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}

	switch ref.Kind() {
	case KindElasticIP:
		return resolveElasticIP(ctx, reader, ref)
	case KindL2Network:
		var l2 juneauv1alpha1.L2Network
		if err := reader.Get(ctx, client.ObjectKey{Name: ref.L2Network}, &l2); err != nil {
			return nil, err
		}
		return fromL2Network(ref, &l2), nil
	default:
		var subnet juneauv1alpha1.Subnet
		if err := reader.Get(ctx, client.ObjectKey{Name: ref.Subnet}, &subnet); err != nil {
			return nil, err
		}
		return fromSubnet(ref, &subnet), nil
	}
}

// ResolveOptional behaves like Resolve but reports a missing object as
// (nil, nil). Admission paths use it where a dangling reference is
// reported as a field error rather than aborting the request.
func ResolveOptional(ctx context.Context, reader client.Reader, ref Reference) (*Network, error) {
	network, err := Resolve(ctx, reader, ref)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return network, err
}

func resolveElasticIP(ctx context.Context, reader client.Reader, ref Reference) (*Network, error) {
	var elasticIP juneauv1alpha1.ElasticIP
	if err := reader.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.ElasticIP}, &elasticIP); err != nil {
		return nil, err
	}

	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := reader.Get(ctx, client.ObjectKey{Name: elasticIP.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		return nil, fmt.Errorf("read the ExternalNetwork of %s: %w", ref, err)
	}

	return &Network{
		Reference: ref,
		ElasticIP: &ElasticIPBinding{
			Address:         elasticIP.Status.Address,
			Attachment:      elasticIP.Status.Attachment.DeepCopy(),
			ExternalNetwork: externalNetwork.Name,
			NetworkID:       externalNetwork.Status.NetworkID,
		},
	}, nil
}

func fromSubnet(ref Reference, subnet *juneauv1alpha1.Subnet) *Network {
	return &Network{
		Reference:  ref,
		Vpc:        subnet.Spec.Vpc,
		CIDR:       subnet.Spec.CIDR,
		Gateway:    subnet.Status.Gateway,
		HasGateway: true,
	}
}

func fromL2Network(ref Reference, l2 *juneauv1alpha1.L2Network) *Network {
	return &Network{
		Reference:  ref,
		Vpc:        l2.Spec.Vpc,
		CIDR:       l2.Spec.CIDR,
		Gateway:    l2.Status.Gateway,
		HasGateway: l2.Spec.Gateway != nil,
	}
}

// L2NetworkGatewayAddress is the address the gateway port of a segment
// answers on: spec.gateway.address when the user pinned one, the first
// address of spec.cidr otherwise. The empty string means the segment
// declares no gateway at all.
//
// The controller publishes the result in status and the admission
// webhook checks it against the addresses the segment has already
// handed out, so both have to read the same rule out of the same spec.
func L2NetworkGatewayAddress(l2 *juneauv1alpha1.L2Network) (string, error) {
	if l2.Spec.Gateway == nil {
		return "", nil
	}
	if l2.Spec.Gateway.Address != "" {
		return l2.Spec.Gateway.Address, nil
	}

	prefix, err := netip.ParsePrefix(l2.Spec.CIDR)
	if err != nil {
		return "", fmt.Errorf("spec.gateway needs a parsable spec.cidr to take its address from: %w", err)
	}
	addr, ok := addressrange.FirstAddr(prefix)
	if !ok {
		return "", fmt.Errorf("spec.cidr %q has no address for a gateway to answer on", l2.Spec.CIDR)
	}
	return addr.String(), nil
}
