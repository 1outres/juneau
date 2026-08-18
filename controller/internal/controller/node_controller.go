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
	stderrors "errors"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// NodeReconciler reconciles a Node object for BGPNodeState provisioning,
// allocates a default-Subnet IP for the node's juneau_node iface, and
// owns the kind=Node NetworkEndpoint that publishes that iface's
// identity.
type NodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// EndpointNamespace is the namespace the kind=Node NetworkEndpoint
	// lives in. NetworkEndpoint is namespaced and cannot name a
	// cluster-scoped Node as its owner, so it has to go somewhere; this
	// reconciler puts it in the controller's own namespace. The daemon
	// finds it by (kind, nodeName), not by namespace, so the two sides
	// do not have to agree on this value.
	EndpointNamespace string
}

// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=bgpnodestates,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkendpoints,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets,verbs=get;list;watch

// Reconcile creates a BGPNodeState for a Node, ensures an
// AllocationClaim against the default Subnet's IP pool, and publishes
// the resulting IP and MAC on the Node's kind=Node NetworkEndpoint so
// the daemon can configure the juneau_node iface to match.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var node corev1.Node
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if errors.IsNotFound(err) {
			// Node has been removed: clean up the associated
			// kind=Node NetworkEndpoint. The AllocationClaim is
			// GC'd via OwnerReferences (Node was its owner); NWEP is
			// namespace-scoped and cannot reference a cluster-scoped
			// owner directly, so we delete it here explicitly.
			if cleanupErr := r.deleteJuneauNodeEndpoints(ctx, req.Name, client.ObjectKey{}); cleanupErr != nil {
				logger.Error(cleanupErr, "cleanup juneau_node NetworkEndpoints", "node", req.Name)
				return ctrl.Result{}, cleanupErr
			}
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Node", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !node.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	bgpNodeState := juneauv1alpha1.BGPNodeState{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name,
		},
	}

	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, &bgpNodeState, func() error {
		return controllerutil.SetControllerReference(&node, &bgpNodeState, r.Scheme)
	}); err != nil {
		logger.Error(err, "unable to create or update BGPNodeState", "name", node.Name)
		return ctrl.Result{}, err
	}

	if err := r.ensureJuneauNodeClaim(ctx, &node); err != nil {
		logger.Error(err, "unable to ensure default-Subnet AllocationClaim", "name", node.Name)
		return ctrl.Result{}, err
	}

	requeue, err := r.ensureJuneauNodeEndpoint(ctx, &node)
	if err != nil {
		logger.Error(err, "unable to ensure juneau_node NetworkEndpoint", "name", node.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{Requeue: requeue}, nil
}

// ensureJuneauNodeClaim creates (or refreshes) an AllocationClaim that
// allocates one IP from the default Subnet's IP pool for this Node. The
// controller turns it into the Node's NetworkEndpoint identity.
func (r *NodeReconciler) ensureJuneauNodeClaim(ctx context.Context, node *corev1.Node) error {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}
	poolName := SubnetIPAllocationPoolName(JuneauNodeDefaultSubnet)
	claim := newAllocationClaim(poolName, gvk, "", node.Name, JuneauNodeAllocationAttribute)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(poolName, gvk, "", node.Name, JuneauNodeAllocationAttribute).Spec
		return controllerutil.SetControllerReference(node, claim, r.Scheme)
	})
	return err
}

const (
	// JuneauNodeDefaultSubnet is the Subnet whose IP pool the per-Node
	// juneau_node iface allocates from.
	JuneauNodeDefaultSubnet = "default"
	// JuneauNodeAllocationAttribute is the AllocationClaim attribute
	// label used for per-Node juneau_node IP claims.
	JuneauNodeAllocationAttribute = "juneauNode.assignedIP"
)

// JuneauNodeClaimName returns the deterministic AllocationClaim name
// for a given Node's juneau_node IP.
func JuneauNodeClaimName(nodeName string) string {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}
	return allocationClaimName(SubnetIPAllocationPoolName(JuneauNodeDefaultSubnet), gvk, "", nodeName, JuneauNodeAllocationAttribute)
}

// ensureJuneauNodeEndpoint publishes the Node's juneau_node identity —
// its default-Subnet IP and the MAC derived from it — on a kind=Node
// NetworkEndpoint. The daemon reads the object and makes the kernel
// match it, so the identity survives a reboot that destroys the veth.
//
// The returned bool asks the caller to requeue: it is set when the
// existing endpoint carried a different identity and was deleted, so
// the next pass can create the replacement.
func (r *NodeReconciler) ensureJuneauNodeEndpoint(ctx context.Context, node *corev1.Node) (bool, error) {
	if r.EndpointNamespace == "" {
		return false, stderrors.New("NodeReconciler.EndpointNamespace must be set")
	}

	claimName := JuneauNodeClaimName(node.Name)
	var claim juneauv1alpha1.AllocationClaim
	if err := r.Get(ctx, client.ObjectKey{Name: claimName}, &claim); err != nil {
		if errors.IsNotFound(err) {
			// The claim was only just created and has not reached the
			// cache yet. Its own reconcile enqueues us again.
			return false, nil
		}
		return false, fmt.Errorf("get AllocationClaim %q: %w", claimName, err)
	}
	if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.IP == "" {
		return false, nil
	}

	desired, err := r.juneauNodeEndpointSpec(ctx, node.Name, claim.Status.Value.IP)
	if err != nil {
		return false, err
	}

	key := client.ObjectKey{
		Namespace: r.EndpointNamespace,
		Name:      juneauv1alpha1.JuneauNodeEndpointName(node.Name),
	}
	var current juneauv1alpha1.NetworkEndpoint
	err = r.Get(ctx, key, &current)
	if errors.IsNotFound(err) {
		// Older daemons created this endpoint themselves, in their own
		// namespace. Drop anything like that before adding ours: two
		// kind=Node endpoints would give the Node two MACs on the
		// overlay and the daemon refuses to pick between them.
		if sweepErr := r.deleteJuneauNodeEndpoints(ctx, node.Name, key); sweepErr != nil {
			return false, sweepErr
		}
		endpoint := &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Spec:       *desired,
		}
		if createErr := r.Create(ctx, endpoint); createErr != nil {
			return false, fmt.Errorf("create NetworkEndpoint %s: %w", key, createErr)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get NetworkEndpoint %s: %w", key, err)
	}

	if juneauNodeEndpointIdentityEqual(&current.Spec, desired) {
		// Deliberately no Update: spec.attachment belongs to the
		// daemon and writing the desired spec would erase it.
		return false, nil
	}

	log.FromContext(ctx).Info("juneau_node NetworkEndpoint identity changed, recreating it",
		"endpoint", key.String(),
		"oldAddress", current.Spec.Address, "oldMACAddress", current.Spec.MACAddress,
		"newAddress", desired.Address, "newMACAddress", desired.MACAddress)
	if err := r.Delete(ctx, &current); err != nil && !errors.IsNotFound(err) {
		return false, fmt.Errorf("delete NetworkEndpoint %s: %w", key, err)
	}
	return true, nil
}

// juneauNodeEndpointSpec builds the identity the daemon has to realize:
// the claimed IP carrying the default Subnet's prefix length, plus the
// MAC derived from that IP. spec.attachment stays unset because only
// the daemon knows the local veth.
func (r *NodeReconciler) juneauNodeEndpointSpec(ctx context.Context, nodeName, ip string) (*juneauv1alpha1.NetworkEndpointSpec, error) {
	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: JuneauNodeDefaultSubnet}, &subnet); err != nil {
		return nil, fmt.Errorf("get Subnet %q: %w", JuneauNodeDefaultSubnet, err)
	}
	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return nil, fmt.Errorf("parse Subnet %q CIDR %q: %w", JuneauNodeDefaultSubnet, subnet.Spec.CIDR, err)
	}
	prefixLen, _ := cidr.Mask.Size()

	address := net.ParseIP(ip)
	mac, err := endpointMAC(address)
	if err != nil {
		return nil, fmt.Errorf("juneau_node address %q: %w", ip, err)
	}

	return &juneauv1alpha1.NetworkEndpointSpec{
		Kind:       juneauv1alpha1.EndpointKindNode,
		NodeName:   nodeName,
		Subnet:     JuneauNodeDefaultSubnet,
		Address:    fmt.Sprintf("%s/%d", address.String(), prefixLen),
		MACAddress: mac,
	}, nil
}

// juneauNodeEndpointIdentityEqual compares the fields the NetworkEndpoint
// webhook makes immutable. A difference means the endpoint has to be
// replaced rather than updated.
func juneauNodeEndpointIdentityEqual(current, desired *juneauv1alpha1.NetworkEndpointSpec) bool {
	return current.Kind == desired.Kind &&
		current.NodeName == desired.NodeName &&
		current.Subnet == desired.Subnet &&
		current.Address == desired.Address &&
		current.MACAddress == desired.MACAddress
}

// deleteJuneauNodeEndpoints removes every kind=Node NetworkEndpoint
// belonging to the named Node except the one at keep. Pass a zero key
// to remove all of them.
//
// The list is cluster-wide: the endpoint this reconciler writes lives
// in EndpointNamespace, but older daemons wrote their own in the
// daemon's namespace, which is a different one.
func (r *NodeReconciler) deleteJuneauNodeEndpoints(ctx context.Context, nodeName string, keep client.ObjectKey) error {
	var list juneauv1alpha1.NetworkEndpointList
	if err := r.List(ctx, &list); err != nil {
		return fmt.Errorf("list NetworkEndpoints: %w", err)
	}
	for i := range list.Items {
		endpoint := &list.Items[i]
		if endpoint.Spec.Kind != juneauv1alpha1.EndpointKindNode {
			continue
		}
		if endpoint.Spec.NodeName != nodeName {
			continue
		}
		if client.ObjectKeyFromObject(endpoint) == keep {
			continue
		}
		if err := r.Delete(ctx, endpoint); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("delete NetworkEndpoint %s/%s: %w", endpoint.Namespace, endpoint.Name, err)
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Owns(&juneauv1alpha1.AllocationClaim{}).
		Watches(
			&juneauv1alpha1.NetworkEndpoint{},
			handler.EnqueueRequestsFromMapFunc(mapJuneauNodeEndpointToNode),
			builder.WithPredicates(juneauNodeEndpointPredicate),
		).
		Named("node").
		Complete(r)
}

// mapJuneauNodeEndpointToNode sends a kind=Node NetworkEndpoint back to
// the Node it belongs to. Owns cannot do this: the endpoint is
// namespaced and a Node is cluster-scoped, so it carries no
// OwnerReference. Without the watch, an endpoint deleted outside the
// controller stays gone until some unrelated Node update happens to
// come along, and the node's daemon has nothing to converge toward in
// the meantime.
func mapJuneauNodeEndpointToNode(_ context.Context, obj client.Object) []reconcile.Request {
	endpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok || endpoint.Spec.NodeName == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{Name: endpoint.Spec.NodeName},
	}}
}

// juneauNodeEndpointPredicate keeps Pod endpoints out of the Node work
// queue. There is one per Pod interface in the cluster and they come
// and go with every Pod, but none of them says anything about a Node.
var juneauNodeEndpointPredicate = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	endpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	return ok && endpoint.Spec.Kind == juneauv1alpha1.EndpointKindNode
})
