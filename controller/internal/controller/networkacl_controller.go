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
	"reflect"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const networkACLRequeueAfter = 200 * time.Millisecond

// NetworkACLReconciler reconciles a NetworkACL object.
//
// Responsibilities:
//
//   - Allocate a cluster-wide ACLID via an AllocationClaim against the
//     network-acl-id pool.
//   - Validate the spec at admission time (vpc exists). Webhook handles
//     the structural part (priority unique, port shape, action enum,
//     immutable vpc); this reconciler re-validates referential pieces
//     (vpc) so drift after admission surfaces on status.
//   - Project a flat ruleset summary (counts, ruleset version, default
//     mode flags) into status so daemons can detect when they are up
//     to date.
//   - Track Subnets that reference this ACL (status.attachedSubnets).
//
// Daemons do NOT read NetworkACL spec to drive BPF maps directly: they
// use the daemon-side reconciler in
// daemon/internal/daemon/dataplane/reconciler/networkacl.go which owns
// the rule expansion + BPF write path. Status mirroring here is for
// observability and Subnet-side reference resolution.
type NetworkACLReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkacls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkacls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkacls/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete

func (r *NetworkACLReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.NetworkACL
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get NetworkACL", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		// AllocationClaim is owned by the NetworkACL and GC'd by the
		// API server; no finalizer required here.
		return ctrl.Result{}, nil
	}

	// 1. Vpc must exist.
	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			if err := r.updateStatusError(ctx, &resource, juneauv1alpha1.NetworkACLReasonVpcNotFound,
				fmt.Sprintf("Vpc %q not found", resource.Spec.Vpc)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: networkACLRequeueAfter}, nil
		}
		return ctrl.Result{}, err
	}

	// 2. ACLID allocation.
	gvk := schema.GroupVersionKind{
		Group:   juneauv1alpha1.GroupVersion.Group,
		Version: juneauv1alpha1.GroupVersion.Version,
		Kind:    "NetworkACL",
	}
	claim, err := r.ensureACLIDClaim(ctx, &resource, gvk)
	if err != nil {
		if updateErr := r.updateStatusError(ctx, &resource, juneauv1alpha1.NetworkACLReasonAllocationFailed,
			fmt.Sprintf("failed to ensure aclID allocation claim: %v", err)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	aclID := resource.Status.ACLID
	if claim.Status.Phase == juneauv1alpha1.AllocationClaimPhaseAllocated && claim.Status.Value.Number > 0 {
		if claim.Status.Value.Number > uint64(^uint32(0)) {
			if err := r.updateStatusError(ctx, &resource, juneauv1alpha1.NetworkACLReasonAllocationFailed,
				fmt.Sprintf("allocated aclID %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		aclID = uint32(claim.Status.Value.Number)
	}
	if aclID == 0 {
		if err := r.updateStatusPending(ctx, &resource, juneauv1alpha1.NetworkACLReasonAllocating,
			"waiting for aclID allocation"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: networkACLRequeueAfter}, nil
	}

	// 3. Ruleset summary.
	summary := summarizeNetworkACLRules(&resource.Spec)
	overBudget := summary.overBudgetMessage()

	// 4. Track attached Subnets (observability + so AttachedSubnets fan-
	// out reaches the daemon side via the controller's informer).
	attached, err := r.listAttachedSubnets(ctx, &resource)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 5. Ruleset version + status write.
	rulesetVersion := r.nextRulesetVersion(&resource, summary)

	rulesValidCondition := metav1.Condition{
		Type:    juneauv1alpha1.NetworkACLConditionRulesValid,
		Status:  metav1.ConditionTrue,
		Reason:  juneauv1alpha1.NetworkACLReasonReconcileSucceeded,
		Message: "",
	}
	readyCondition := metav1.Condition{
		Type:    juneauv1alpha1.NetworkACLConditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  juneauv1alpha1.NetworkACLReasonReconcileSucceeded,
		Message: "",
	}
	if overBudget != "" {
		rulesValidCondition.Status = metav1.ConditionFalse
		rulesValidCondition.Reason = juneauv1alpha1.NetworkACLReasonRuleLimitExceeded
		rulesValidCondition.Message = overBudget
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = juneauv1alpha1.NetworkACLReasonRuleLimitExceeded
		readyCondition.Message = overBudget
	}

	return ctrl.Result{}, r.updateStatus(ctx, &resource, networkACLStatusUpdate{
		aclID:          aclID,
		summary:        summary,
		rulesetVersion: rulesetVersion,
		attached:       attached,
		conditions:     []metav1.Condition{rulesValidCondition, readyCondition},
	})
}

func (r *NetworkACLReconciler) ensureACLIDClaim(ctx context.Context, resource *juneauv1alpha1.NetworkACL, gvk schema.GroupVersionKind) (*juneauv1alpha1.AllocationClaim, error) {
	claim := newAllocationClaim(allocationPoolNetworkACLID, gvk, "", resource.Name, "status.aclID")
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(allocationPoolNetworkACLID, gvk, "", resource.Name, "status.aclID").Spec
		return controllerutil.SetControllerReference(resource, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

// networkACLRuleSummary is everything the controller publishes about a
// spec's rules. It separates the two numbers that used to be conflated:
// the rule count is what the user wrote, the entry count is what those
// rules cost in the data plane. Capacity is budgeted against the entry
// count alone.
type networkACLRuleSummary struct {
	ingressRuleCount  int32
	egressRuleCount   int32
	ingressEntryCount int32
	egressEntryCount  int32
	hasIngressRules   bool
	hasEgressRules    bool
}

// summarizeNetworkACLRules counts both rules and entries per direction
// and records the has*Rules booleans that distinguish "spec omitted the
// direction" (default-allow) from "spec set the direction explicitly,
// even if empty" (default-deny). Mirrors the SG summarize helper.
func summarizeNetworkACLRules(spec *juneauv1alpha1.NetworkACLSpec) networkACLRuleSummary {
	var summary networkACLRuleSummary
	if spec.Ingress != nil {
		summary.hasIngressRules = true
		summary.ingressRuleCount = int32(len(*spec.Ingress))
		summary.ingressEntryCount = int32(juneauv1alpha1.NetworkACLDirectionEntryCount(*spec.Ingress))
	}
	if spec.Egress != nil {
		summary.hasEgressRules = true
		summary.egressRuleCount = int32(len(*spec.Egress))
		summary.egressEntryCount = int32(juneauv1alpha1.NetworkACLDirectionEntryCount(*spec.Egress))
	}
	return summary
}

// overBudgetMessage describes every direction whose entries do not fit
// NetworkACLMaxEntriesPerDirection, or "" when the spec fits. The
// message names the direction, its entry count and the limit, and
// spells out how rules turn into entries: an operator who wrote two
// rules cannot otherwise tell why the count is thirty-two.
func (s networkACLRuleSummary) overBudgetMessage() string {
	var over []string
	if s.ingressEntryCount > juneauv1alpha1.NetworkACLMaxEntriesPerDirection {
		over = append(over, fmt.Sprintf("ingress rule count %d needs %d entries", s.ingressRuleCount, s.ingressEntryCount))
	}
	if s.egressEntryCount > juneauv1alpha1.NetworkACLMaxEntriesPerDirection {
		over = append(over, fmt.Sprintf("egress rule count %d needs %d entries", s.egressRuleCount, s.egressEntryCount))
	}
	if len(over) == 0 {
		return ""
	}
	return fmt.Sprintf("%s, but a direction holds at most %d entries; a rule costs one entry per port, so drop ports or move rules to another NetworkACL",
		strings.Join(over, " and "), juneauv1alpha1.NetworkACLMaxEntriesPerDirection)
}

// nextRulesetVersion returns the version to record on status. We bump on
// any observable summary change (rule counts, entry counts, has*Rules
// flags, generation) so daemons can detect "the ruleset I have differs
// from the published one" without a deep diff.
func (r *NetworkACLReconciler) nextRulesetVersion(resource *juneauv1alpha1.NetworkACL, summary networkACLRuleSummary) uint64 {
	if networkACLSummaryFromStatus(resource.Status) == summary &&
		resource.Status.ObservedGeneration == resource.Generation &&
		resource.Status.RulesetVersion > 0 {
		return resource.Status.RulesetVersion
	}
	return resource.Status.RulesetVersion + 1
}

// networkACLSummaryFromStatus reads back the summary a previous
// reconcile published, so error and pending paths can rewrite status
// without inventing new counts.
func networkACLSummaryFromStatus(status juneauv1alpha1.NetworkACLStatus) networkACLRuleSummary {
	return networkACLRuleSummary{
		ingressRuleCount:  status.IngressRuleCount,
		egressRuleCount:   status.EgressRuleCount,
		ingressEntryCount: status.IngressEntryCount,
		egressEntryCount:  status.EgressEntryCount,
		hasIngressRules:   status.HasIngressRules,
		hasEgressRules:    status.HasEgressRules,
	}
}

// listAttachedSubnets enumerates Subnets whose spec.networkACL points
// at this ACL. Sorted for deterministic status diffs.
func (r *NetworkACLReconciler) listAttachedSubnets(ctx context.Context, resource *juneauv1alpha1.NetworkACL) ([]string, error) {
	var subnets juneauv1alpha1.SubnetList
	if err := r.List(ctx, &subnets); err != nil {
		return nil, err
	}
	out := make([]string, 0)
	for i := range subnets.Items {
		s := &subnets.Items[i]
		if s.Spec.NetworkACL != resource.Name {
			continue
		}
		// Cross-Vpc references are rejected by the Subnet webhook,
		// but we double-check here in case admission was somehow
		// bypassed (e.g. controller-only environments).
		if s.Spec.Vpc != resource.Spec.Vpc {
			continue
		}
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out, nil
}

type networkACLStatusUpdate struct {
	aclID          uint32
	summary        networkACLRuleSummary
	rulesetVersion uint64
	attached       []string
	conditions     []metav1.Condition
}

func (r *NetworkACLReconciler) updateStatus(ctx context.Context, resource *juneauv1alpha1.NetworkACL, u networkACLStatusUpdate) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = resource.Generation
	updated.Status.ACLID = u.aclID
	updated.Status.IngressRuleCount = u.summary.ingressRuleCount
	updated.Status.EgressRuleCount = u.summary.egressRuleCount
	updated.Status.IngressEntryCount = u.summary.ingressEntryCount
	updated.Status.EgressEntryCount = u.summary.egressEntryCount
	updated.Status.HasIngressRules = u.summary.hasIngressRules
	updated.Status.HasEgressRules = u.summary.hasEgressRules
	updated.Status.RulesetVersion = u.rulesetVersion
	updated.Status.AttachedSubnets = u.attached

	for _, c := range u.conditions {
		c.ObservedGeneration = resource.Generation
		meta.SetStatusCondition(&updated.Status.Conditions, c)
	}

	if reflect.DeepEqual(resource.Status, updated.Status) {
		return nil
	}
	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

func (r *NetworkACLReconciler) updateStatusError(ctx context.Context, resource *juneauv1alpha1.NetworkACL, reason, message string) error {
	rulesValid := metav1.Condition{
		Type:    juneauv1alpha1.NetworkACLConditionRulesValid,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	}
	ready := metav1.Condition{
		Type:    juneauv1alpha1.NetworkACLConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	}
	return r.updateStatus(ctx, resource, networkACLStatusUpdate{
		aclID:          resource.Status.ACLID,
		summary:        networkACLSummaryFromStatus(resource.Status),
		rulesetVersion: resource.Status.RulesetVersion,
		attached:       resource.Status.AttachedSubnets,
		conditions:     []metav1.Condition{rulesValid, ready},
	})
}

func (r *NetworkACLReconciler) updateStatusPending(ctx context.Context, resource *juneauv1alpha1.NetworkACL, reason, message string) error {
	ready := metav1.Condition{
		Type:    juneauv1alpha1.NetworkACLConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	}
	return r.updateStatus(ctx, resource, networkACLStatusUpdate{
		aclID:          resource.Status.ACLID,
		summary:        networkACLSummaryFromStatus(resource.Status),
		rulesetVersion: resource.Status.RulesetVersion,
		attached:       resource.Status.AttachedSubnets,
		conditions:     []metav1.Condition{ready},
	})
}

// SetupWithManager wires informers. Subnet attachment is the primary
// source of fan-out: when a Subnet's spec.networkACL flips, both the
// old and new ACLs need to recompute their AttachedSubnets list.
func (r *NetworkACLReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.NetworkACL{}).
		Watches(&juneauv1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToACL)).
		Watches(&juneauv1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapSubnetToACLs)).
		Named("networkacl").
		Complete(r)
}

func (r *NetworkACLReconciler) mapClaimToACL(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "NetworkACL" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

// mapSubnetToACLs re-enqueues whichever ACL(s) a Subnet's spec.networkACL
// references. We can only see the *current* spec; when the user flips
// the reference, the previously-attached ACL also needs a reconcile so
// it removes the Subnet from its AttachedSubnets list. The cheap way
// to do that without comparing old vs new is to enqueue every ACL in
// the same Vpc and let each reconcile recompute its own membership.
func (r *NetworkACLReconciler) mapSubnetToACLs(ctx context.Context, obj client.Object) []reconcile.Request {
	subnet, ok := obj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil
	}
	var list juneauv1alpha1.NetworkACLList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, acl := range list.Items {
		if acl.Spec.Vpc != subnet.Spec.Vpc {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: acl.Name}})
	}
	return reqs
}
