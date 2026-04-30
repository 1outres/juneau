package bootstrap

import (
	"context"
	"fmt"
	"net"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// JuneauNodeEndpointName is the deterministic NetworkEndpoint name for
// the per-node juneau_node pseudo-pod. Same form across daemon restarts
// so the resource is updated in place rather than re-created.
func JuneauNodeEndpointName(nodeName string) string {
	return "juneau-node." + nodeName
}

// EnsureJuneauNodeEndpoint creates or updates the NetworkEndpoint that
// represents this node's juneau_node pseudo-pod on the default Subnet.
// It is the only kind=Node endpoint juneau emits; data plane reconcilers
// (arp/fdb/pod-iface/attacher) pick it up just like a Pod NWEP.
//
// Called after SetupDefaultGatewayIface so the veth's ifindex/MAC are
// known. The resource lives in the daemon's own namespace so it shares
// RBAC with Pod NWEPs.
func EnsureJuneauNodeEndpoint(
	ctx context.Context,
	cl client.Client,
	namespace string,
	nodeName string,
	info *JuneauNodeIfaceInfo,
	subnetName string,
) error {
	if info == nil {
		return fmt.Errorf("juneau_node iface info is nil")
	}

	var subnet juneauv1alpha1.Subnet
	if err := cl.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
		return fmt.Errorf("get Subnet %q: %w", subnetName, err)
	}
	_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return fmt.Errorf("parse subnet CIDR %q: %w", subnet.Spec.CIDR, err)
	}
	address := (&net.IPNet{IP: info.AssignedIP, Mask: ipnet.Mask}).String()

	desired := juneauv1alpha1.NetworkEndpointSpec{
		Kind:       juneauv1alpha1.EndpointKindNode,
		NodeName:   nodeName,
		Subnet:     subnetName,
		Address:    address,
		MACAddress: info.HostSideMAC.String(),
		Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
			Ifindex:        info.Ifindex,
			HostMACAddress: info.HostSideMAC.String(),
		},
	}

	name := JuneauNodeEndpointName(nodeName)
	current := &juneauv1alpha1.NetworkEndpoint{}
	err = cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, current)
	if apierrors.IsNotFound(err) {
		obj := &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
			},
			Spec: desired,
		}
		return cl.Create(ctx, obj)
	}
	if err != nil {
		return fmt.Errorf("get NetworkEndpoint %s/%s: %w", namespace, name, err)
	}

	// Identity fields (kind, nodeName, subnet, address, macAddress) are
	// immutable per the NWEP webhook. Only the attachment may change
	// across daemon restarts (ifindex differs after a reboot). If
	// anything else drifted, surface the conflict rather than papering
	// over it.
	if current.Spec.Kind != desired.Kind ||
		current.Spec.NodeName != desired.NodeName ||
		current.Spec.Subnet != desired.Subnet ||
		current.Spec.Address != desired.Address ||
		current.Spec.MACAddress != desired.MACAddress {
		return fmt.Errorf("juneau_node NetworkEndpoint %s/%s identity drifted; manual cleanup required (existing=%+v desired=%+v)",
			namespace, name, current.Spec, desired)
	}

	if current.Spec.Attachment != nil &&
		current.Spec.Attachment.Ifindex == desired.Attachment.Ifindex &&
		current.Spec.Attachment.HostMACAddress == desired.Attachment.HostMACAddress {
		return nil
	}
	current.Spec.Attachment = desired.Attachment
	return cl.Update(ctx, current)
}
