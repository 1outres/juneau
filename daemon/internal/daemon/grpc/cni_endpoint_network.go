package grpc

import (
	"context"
	"fmt"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// podEndpointNetwork is the segment the NetworkEndpoint of one NIC joins.
// Exactly one field is set, the same rule the NetworkEndpoint follows.
type podEndpointNetwork struct {
	subnet          string
	l2Network       string
	externalNetwork string
}

// podEndpointNetwork reads the segment the NetworkEndpoint of a NIC joins.
//
// A Subnet and an L2Network are named on the NIC itself. A NIC on an
// ElasticIP joins the ExternalNetwork of that ElasticIP: the data plane
// forwards to it on the network ID of that ExternalNetwork.
func (c *CNIServer) podEndpointNetwork(ctx context.Context, nwiface *juneauv1alpha1.NetworkInterface) (podEndpointNetwork, error) {
	switch {
	case nwiface.Spec.Subnet != "":
		return podEndpointNetwork{subnet: nwiface.Spec.Subnet}, nil
	case nwiface.Spec.L2Network != "":
		return podEndpointNetwork{l2Network: nwiface.Spec.L2Network}, nil
	case nwiface.Spec.ElasticIP != "":
		externalNetwork, err := c.elasticIPExternalNetwork(ctx, nwiface)
		if err != nil {
			return podEndpointNetwork{}, err
		}
		return podEndpointNetwork{externalNetwork: externalNetwork}, nil
	default:
		return podEndpointNetwork{}, makeError(cnipb.ErrorCode_INTERNAL, "The NetworkInterface names no network",
			fmt.Sprintf("networkInterface=%s/%s", nwiface.Namespace, nwiface.Name))
	}
}

func (c *CNIServer) elasticIPExternalNetwork(ctx context.Context, nwiface *juneauv1alpha1.NetworkInterface) (string, error) {
	key := client.ObjectKey{Namespace: nwiface.Namespace, Name: nwiface.Spec.ElasticIP}
	var elasticIP juneauv1alpha1.ElasticIP
	if err := c.cachedClient.Get(ctx, key, &elasticIP); err != nil {
		zap.L().Error("failed to read the ElasticIP of a NIC", zap.Error(err))
		return "", makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to read the ElasticIP of a NIC", err.Error())
	}
	if elasticIP.Spec.ExternalNetwork == "" {
		return "", makeError(cnipb.ErrorCode_INTERNAL, "The ElasticIP of a NIC names no ExternalNetwork",
			fmt.Sprintf("elasticIP=%s", key))
	}
	return elasticIP.Spec.ExternalNetwork, nil
}

func (n podEndpointNetwork) applyTo(spec *juneauv1alpha1.NetworkEndpointSpec) {
	spec.Subnet = n.subnet
	spec.L2Network = n.l2Network
	spec.ExternalNetwork = n.externalNetwork
}
