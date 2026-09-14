package reconciler

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// endpointNetwork names the kind of segment a NetworkEndpoint joined.
type endpointNetwork int

const (
	endpointOnSubnet endpointNetwork = iota + 1
	endpointOnL2Network
	// endpointOnExternalNetwork is a Pod NIC that carries an ElasticIP
	// directly. Its segment is keyed by ExternalNetwork.status.networkID,
	// which comes from the same number space as the VNI of a Subnet or an
	// L2Network.
	endpointOnExternalNetwork
)

func (n endpointNetwork) String() string {
	switch n {
	case endpointOnSubnet:
		return "Subnet"
	case endpointOnL2Network:
		return "L2Network"
	case endpointOnExternalNetwork:
		return "ExternalNetwork"
	default:
		return fmt.Sprintf("endpointNetwork(%d)", int(n))
	}
}

// endpointNetworkOf reads which kind of segment an endpoint joined. The
// NetworkEndpoint CRD makes exactly one of the three fields required, so an
// endpoint that names none is an error rather than a guess.
func endpointNetworkOf(nwep *juneauv1alpha1.NetworkEndpoint) (endpointNetwork, error) {
	switch {
	case nwep.Spec.Subnet != "":
		return endpointOnSubnet, nil
	case nwep.Spec.L2Network != "":
		return endpointOnL2Network, nil
	case nwep.Spec.ExternalNetwork != "":
		return endpointOnExternalNetwork, nil
	default:
		return 0, fmt.Errorf("NetworkEndpoint %s/%s names no network", nwep.Namespace, nwep.Name)
	}
}

// overlaySegmentID reads the number fdb and arp_table key an endpoint by:
// the VNI of its Subnet, or the network ID of its ExternalNetwork. Both
// tables carry either one the same way, because both numbers come from one
// pool and never collide.
//
// ready is false while an ExternalNetwork is missing or has no network ID
// yet. The caller writes nothing then, since 0 names no segment, and the
// ExternalNetwork fan-out brings the endpoint back once the number lands.
// A Subnet is read as it always was.
func overlaySegmentID(ctx context.Context, cl client.Client, nwep *juneauv1alpha1.NetworkEndpoint, network endpointNetwork) (id uint32, ready bool, err error) {
	switch network {
	case endpointOnSubnet:
		var subnet juneauv1alpha1.Subnet
		if err := cl.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
			return 0, false, err
		}
		return subnet.Status.VNI, true, nil
	case endpointOnExternalNetwork:
		var externalNetwork juneauv1alpha1.ExternalNetwork
		err := cl.Get(ctx, client.ObjectKey{Name: nwep.Spec.ExternalNetwork}, &externalNetwork)
		if apierrors.IsNotFound(err) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, err
		}
		if externalNetwork.Status.NetworkID == 0 {
			return 0, false, nil
		}
		return externalNetwork.Status.NetworkID, true, nil
	default:
		return 0, false, fmt.Errorf("NetworkEndpoint %s/%s on a %s has no overlay segment in fdb or arp_table", nwep.Namespace, nwep.Name, network)
	}
}

// externalNetworkEndpointKeys lists the endpoints on the ExternalNetwork of
// an informer event.
func externalNetworkEndpointKeys(cl client.Client, obj any) []string {
	externalNetwork, ok := externalNetworkFromEvent(obj)
	if !ok {
		return nil
	}

	var list juneauv1alpha1.NetworkEndpointList
	if err := cl.List(context.Background(), &list); err != nil {
		return nil
	}
	keys := make([]string, 0, len(list.Items))
	for i := range list.Items {
		endpoint := &list.Items[i]
		if endpoint.Spec.ExternalNetwork != externalNetwork.Name {
			continue
		}
		keys = append(keys, endpoint.Namespace+"/"+endpoint.Name)
	}
	return keys
}

func externalNetworkFromEvent(obj any) (*juneauv1alpha1.ExternalNetwork, bool) {
	if network, ok := obj.(*juneauv1alpha1.ExternalNetwork); ok {
		return network, true
	}
	tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown)
	if !ok {
		return nil, false
	}
	network, ok := tombstone.Obj.(*juneauv1alpha1.ExternalNetwork)
	return network, ok
}
