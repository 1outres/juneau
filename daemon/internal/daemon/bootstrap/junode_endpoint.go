package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// patchJuneauNodeAttachment records the local juneau_node veth on the
// kind=Node NetworkEndpoint the controller published for this node.
//
// Only spec.attachment is written. The identity fields (kind, nodeName,
// subnet, address, macAddress) belong to the controller and are
// immutable per the NetworkEndpoint webhook, so the daemon must never
// send them. The attachment itself is node-local and changes whenever
// the veth is re-created, which is why the controller never writes it.
//
// The endpoint comes from the caller, so one convergence pass reads the
// object once and both halves of it work from the same read.
//
// That read comes from the informer cache, so the controller can have
// moved the object on before this write lands. It does exactly that on
// an identity change, which is when the daemon writes here in the first
// place, so a conflict is expected rather than a fault: retry from the
// version that won instead of reporting it.
func patchJuneauNodeAttachment(
	ctx context.Context,
	cl client.Client,
	endpoint *juneauv1alpha1.NetworkEndpoint,
	info *JuneauNodeIfaceInfo,
) error {
	if info == nil {
		return fmt.Errorf("juneau_node iface info is nil")
	}

	desired := &juneauv1alpha1.NetworkEndpointAttachment{
		Ifindex:        info.Ifindex,
		HostMACAddress: info.HostSideMAC.String(),
	}
	key := client.ObjectKeyFromObject(endpoint)
	current := endpoint.DeepCopy()

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if current.Spec.Attachment != nil && *current.Spec.Attachment == *desired {
			return nil
		}

		current.Spec.Attachment = desired
		err := cl.Update(ctx, current)
		if apierrors.IsConflict(err) {
			// Re-read so the next attempt carries a resourceVersion the
			// server still accepts.
			fresh := &juneauv1alpha1.NetworkEndpoint{}
			if getErr := cl.Get(ctx, key, fresh); getErr != nil {
				return getErr
			}
			current = fresh
		}
		return err
	})
}

// ErrJuneauNodeEndpointNotFound reports that the controller has not
// published this node's kind=Node NetworkEndpoint.
//
// It means different things to the two callers. At startup it is fatal:
// the daemon has no identity to realize, so it exits and the DaemonSet
// restart is the retry. On the work queue it is a normal gap, because
// the controller deletes and recreates the object whenever the node's
// identity changes.
var ErrJuneauNodeEndpointNotFound = errors.New("no kind=Node NetworkEndpoint")

// FindJuneauNodeEndpoint returns the kind=Node NetworkEndpoint the
// controller published for this node.
//
// The lookup is by identity rather than by namespace and name because
// the controller and the daemon are deployed in different namespaces
// and neither knows the other's. A node has exactly one kind=Node
// endpoint, so the pair (kind, nodeName) already names it; more than
// one match means a leftover from an older layout is still around, and
// programming both would give the node two MACs on the overlay.
func FindJuneauNodeEndpoint(ctx context.Context, cl client.Client, nodeName string) (*juneauv1alpha1.NetworkEndpoint, error) {
	var list juneauv1alpha1.NetworkEndpointList
	if err := cl.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list NetworkEndpoints: %w", err)
	}

	var found []*juneauv1alpha1.NetworkEndpoint
	for i := range list.Items {
		endpoint := &list.Items[i]
		if endpoint.Spec.Kind != juneauv1alpha1.EndpointKindNode {
			continue
		}
		if endpoint.Spec.NodeName != nodeName {
			continue
		}
		found = append(found, endpoint)
	}

	switch len(found) {
	case 0:
		return nil, fmt.Errorf("node %q: %w", nodeName, ErrJuneauNodeEndpointNotFound)
	case 1:
		return found[0], nil
	default:
		names := make([]string, 0, len(found))
		for _, endpoint := range found {
			names = append(names, endpoint.Namespace+"/"+endpoint.Name)
		}
		return nil, fmt.Errorf("node %q has %d kind=Node NetworkEndpoints (%s), want exactly one", nodeName, len(found), strings.Join(names, ", "))
	}
}

// parseJuneauNodeIdentity turns the address and MAC the controller
// published on the kind=Node NetworkEndpoint into the values the veth
// setup needs. Anything missing or unparseable is an error: the daemon
// has no business inventing an identity of its own.
func parseJuneauNodeIdentity(endpoint *juneauv1alpha1.NetworkEndpoint) (*JuneauNodeIdentity, error) {
	ref := endpoint.Namespace + "/" + endpoint.Name

	if endpoint.Spec.Address == "" {
		return nil, fmt.Errorf("NetworkEndpoint %s has no spec.address", ref)
	}
	ip, ipnet, err := net.ParseCIDR(endpoint.Spec.Address)
	if err != nil {
		return nil, fmt.Errorf("parse NetworkEndpoint %s spec.address %q: %w", ref, endpoint.Spec.Address, err)
	}

	if endpoint.Spec.MACAddress == "" {
		return nil, fmt.Errorf("NetworkEndpoint %s has no spec.macAddress", ref)
	}
	mac, err := net.ParseMAC(endpoint.Spec.MACAddress)
	if err != nil {
		return nil, fmt.Errorf("parse NetworkEndpoint %s spec.macAddress %q: %w", ref, endpoint.Spec.MACAddress, err)
	}

	return &JuneauNodeIdentity{
		Address: &net.IPNet{IP: ip, Mask: ipnet.Mask},
		MAC:     mac,
	}, nil
}
