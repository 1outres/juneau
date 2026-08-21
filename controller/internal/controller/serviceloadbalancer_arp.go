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

package controller

import (
	"context"
	"fmt"
	"hash/fnv"
	"slices"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// electARPNode picks the single node that answers ARP requests for vip.
// advertisingNodes are the nodes that hold a ready local backend, and current
// is the node the existing ARPAdvertisement names, or an empty string when
// there is none. An empty result means no node can answer and the
// advertisement has to go.
func electARPNode(vip string, advertisingNodes []string, current string) string {
	if len(advertisingNodes) == 0 {
		return ""
	}

	// Keep the current node while it still qualifies. juneau sends no
	// gratuitous ARP, so every move leaves the VIP unreachable until the
	// peers' neighbor entries age out.
	if slices.Contains(advertisingNodes, current) {
		return current
	}

	elected := ""
	var electedScore uint64
	for _, node := range advertisingNodes {
		score := rendezvousScore(vip, node)
		if elected == "" || score > electedScore || (score == electedScore && node < elected) {
			elected, electedScore = node, score
		}
	}
	return elected
}

// rendezvousScore is the weight of a (vip, node) pair in the rendezvous
// hashing used to pick a node. The separator keeps a VIP that ends with the
// first characters of a node name from scoring like a shorter VIP paired with
// a longer node name.
func rendezvousScore(vip, node string) uint64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(vip))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(node))
	return hash.Sum64()
}

// reconcileARPAdvertisement keeps the ARPAdvertisement in step with the node
// elected for the VIP and returns that node so the caller can mirror it into
// status. It removes the advertisement whenever no node answers: an
// unallocated VIP, no ready local backend, or a bgp ExternalNetwork that
// announces the VIP through the speaker instead.
func (r *ServiceLoadBalancerReconciler) reconcileARPAdvertisement(
	ctx context.Context,
	resource *juneauv1alpha1.ServiceLoadBalancer,
	externalNetwork *juneauv1alpha1.ExternalNetwork,
	vip string,
	advertisingNodes []string,
) (string, error) {
	name := serviceLoadBalancerAdvertisementName(resource.Namespace, resource.Name)

	switch externalNetwork.Spec.Type {
	case juneauv1alpha1.ExternalNetworkTypeBGP:
		return "", deleteARPAdvertisement(ctx, r.Client, name)
	case juneauv1alpha1.ExternalNetworkTypeARP:
		current, err := r.currentARPNode(ctx, name)
		if err != nil {
			return "", err
		}

		elected := electARPNode(vip, advertisingNodes, current)
		if vip == "" || elected == "" {
			return "", deleteARPAdvertisement(ctx, r.Client, name)
		}

		desired := arpAdvertisementSpec{
			Name:            name,
			ExternalNetwork: externalNetwork.Name,
			Address:         vip,
			NodeName:        elected,
		}
		if err := ensureARPAdvertisement(ctx, r.Client, desired, arpAdvertisementDeletedByFinalizer{}); err != nil {
			return "", err
		}
		return elected, nil
	default:
		return "", fmt.Errorf("ExternalNetwork %q has unsupported type %q", externalNetwork.Name, externalNetwork.Spec.Type)
	}
}

// currentARPNode reads the node the existing ARPAdvertisement names. The
// advertisement is the single source of truth for where the VIP answers now,
// so the election sees the same value the data plane does.
func (r *ServiceLoadBalancerReconciler) currentARPNode(ctx context.Context, name string) (string, error) {
	var advertisement juneauv1alpha1.ARPAdvertisement
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &advertisement); err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return advertisement.Spec.NodeName, nil
}

func serviceLoadBalancerAdvertisementName(namespace, name string) string {
	return fmt.Sprintf("slb-%s-%s", namespace, name)
}
