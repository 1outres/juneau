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
// no matter whether a Subnet or an L2Network backs it. The controllers
// and the admission webhooks both build on that view instead of asking
// which of the two kinds a NIC named.
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

// Reference names the network something joins. Exactly one field is
// set; both empty and both filled in are errors the API schema rejects.
type Reference struct {
	Subnet    string
	L2Network string
}

// InterfaceReference reads the network a NetworkInterface joins.
func InterfaceReference(spec juneauv1alpha1.NetworkInterfaceSpec) Reference {
	return Reference{Subnet: spec.Subnet, L2Network: spec.L2Network}
}

// AttachmentReference reads the network a Pod NIC annotation names.
func AttachmentReference(attachment juneauv1alpha1.PodNetworkAttachment) Reference {
	return Reference{Subnet: attachment.Subnet, L2Network: attachment.L2Network}
}

// Kind reports which resource the reference names. It is only
// meaningful once Validate has passed.
func (r Reference) Kind() Kind {
	if r.L2Network != "" {
		return KindL2Network
	}
	return KindSubnet
}

// Name is the object name the reference points at.
func (r Reference) Name() string {
	if r.L2Network != "" {
		return r.L2Network
	}
	return r.Subnet
}

// String renders the reference for messages, e.g. `Subnet "web"`.
func (r Reference) String() string {
	return fmt.Sprintf("%s %q", r.Kind(), r.Name())
}

// AllocationPoolName is the AllocationPool that backs addresses on the
// referenced network. Reading it needs no cluster access, so a caller
// can find the pool of a network that has already been deleted.
func (r Reference) AllocationPoolName() string {
	if r.L2Network != "" {
		return L2NetworkAllocationPoolName(r.L2Network)
	}
	return SubnetAllocationPoolName(r.Subnet)
}

// Validate reports whether the reference names exactly one network.
func (r Reference) Validate() error {
	switch {
	case r.Subnet == "" && r.L2Network == "":
		return fmt.Errorf("neither a Subnet nor an L2Network is named")
	case r.Subnet != "" && r.L2Network != "":
		return fmt.Errorf("both Subnet %q and L2Network %q are named", r.Subnet, r.L2Network)
	}
	return nil
}

// Network is the resolved view of the network a NIC joins. Callers
// program a NIC from this alone and never branch on Kind.
type Network struct {
	// Reference is what named this network.
	Reference Reference

	// Vpc is the Vpc the network belongs to. Every SecurityGroup and
	// NetworkACL a NIC on it uses has to live in the same Vpc.
	Vpc string

	// CIDR is the prefix the network hands addresses out of. Empty for
	// an L2Network that declares none: NICs on it carry no address.
	CIDR string

	// Gateway is the address a NIC on this network routes through.
	// Empty when the network has no gateway.
	Gateway string
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

// Resolve reads the network a reference names. A reference that does
// not name exactly one network is an error, and a named object that
// does not exist comes back as the apierrors NotFound of that object so
// callers can keep telling "missing" apart from "broken".
func Resolve(ctx context.Context, reader client.Reader, ref Reference) (*Network, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}

	if ref.Kind() == KindL2Network {
		var l2 juneauv1alpha1.L2Network
		if err := reader.Get(ctx, client.ObjectKey{Name: ref.L2Network}, &l2); err != nil {
			return nil, err
		}
		return fromL2Network(&l2), nil
	}

	var subnet juneauv1alpha1.Subnet
	if err := reader.Get(ctx, client.ObjectKey{Name: ref.Subnet}, &subnet); err != nil {
		return nil, err
	}
	return fromSubnet(&subnet), nil
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

func fromSubnet(subnet *juneauv1alpha1.Subnet) *Network {
	return &Network{
		Reference: Reference{Subnet: subnet.Name},
		Vpc:       subnet.Spec.Vpc,
		CIDR:      subnet.Spec.CIDR,
		Gateway:   subnet.Status.Gateway,
	}
}

func fromL2Network(l2 *juneauv1alpha1.L2Network) *Network {
	return &Network{
		Reference: Reference{L2Network: l2.Name},
		Vpc:       l2.Spec.Vpc,
		CIDR:      l2.Spec.CIDR,
		Gateway:   l2.Status.Gateway,
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
