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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// NodeReconciler reconciles a Node object for BGPNodeState provisioning
// and allocates a default-Subnet IP for the node's juneau_node iface.
type NodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=bgpnodestates,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkendpoints,verbs=get;list;watch;delete

// Reconcile creates a BGPNodeState for a Node and ensures an
// AllocationClaim against the default Subnet's IP pool so the daemon
// can configure the node's juneau_node iface.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var node corev1.Node
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if errors.IsNotFound(err) {
			// Node has been removed: clean up the associated
			// kind=Node NetworkEndpoint(s). The AllocationClaim is
			// GC'd via OwnerReferences (Node was its owner); NWEP is
			// namespace-scoped and cannot reference a cluster-scoped
			// owner directly, so we delete it here explicitly.
			if cleanupErr := r.cleanupJuneauNodeEndpoints(ctx, req.Name); cleanupErr != nil {
				logger.Error(cleanupErr, "cleanup juneau_node NetworkEndpoints", "node", req.Name)
				return ctrl.Result{}, cleanupErr
			}
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Node", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !node.ObjectMeta.DeletionTimestamp.IsZero() {
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

	return ctrl.Result{}, nil
}

// ensureJuneauNodeClaim creates (or refreshes) an AllocationClaim that
// allocates one IP from the default Subnet's IP pool for this Node. The
// daemon reads it to configure the juneau_node iface.
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
	// label used for per-Node juneau_node IP claims. The daemon scans
	// claims with this attribute to find its assigned IP.
	JuneauNodeAllocationAttribute = "juneauNode.assignedIP"
)

// JuneauNodeClaimName returns the deterministic AllocationClaim name
// for a given Node's juneau_node IP. Daemons can reconstruct it without
// listing.
func JuneauNodeClaimName(nodeName string) string {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}
	return allocationClaimName(SubnetIPAllocationPoolName(JuneauNodeDefaultSubnet), gvk, "", nodeName, JuneauNodeAllocationAttribute)
}

// cleanupJuneauNodeEndpoints removes every NetworkEndpoint that was
// created for the named Node's juneau_node iface. Lists across all
// namespaces because the daemon namespace is operator-configurable.
func (r *NodeReconciler) cleanupJuneauNodeEndpoints(ctx context.Context, nodeName string) error {
	var list juneauv1alpha1.NetworkEndpointList
	if err := r.List(ctx, &list); err != nil {
		return err
	}
	for i := range list.Items {
		ep := &list.Items[i]
		if ep.Spec.Kind != juneauv1alpha1.EndpointKindNode {
			continue
		}
		if ep.Spec.NodeName != nodeName {
			continue
		}
		if err := r.Delete(ctx, ep); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Named("node").
		Complete(r)
}
