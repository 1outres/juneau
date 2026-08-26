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
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const securityGroupRequeueAfter = 200 * time.Millisecond

// SecurityGroupReconciler reconciles a SecurityGroup object.
//
// Responsibilities:
//
//   - Allocate a cluster-wide GroupID via an AllocationClaim against the
//     security-group-id pool.
//   - Validate the spec at admission time (peers exist, ports parse, vpc
//     exists). Webhook handles the structural part; this reconciler
//     re-validates because peers can be deleted after admission.
//   - Project a flat ruleset summary (counts, ruleset version, egress
//     mode) into status so daemons can see when they are up to date.
//   - Track NetworkInterfaces that reference this SG (status.attachedInterfaces).
//
// Daemons do NOT read SecurityGroup spec directly to drive the BPF maps:
// they use the daemon-side reconciler in
// daemon/internal/daemon/dataplane/reconciler/securitygroup.go which
// owns the rule expansion + BPF write path. Status mirroring here is
// observability-only.
type SecurityGroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=securitygroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=securitygroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=securitygroups/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete

func (r *SecurityGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.SecurityGroup
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get SecurityGroup", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		// AllocationClaim has the SecurityGroup as its OwnerRef, so it
		// will be GC'd by Kubernetes once the SG disappears.
		return ctrl.Result{}, nil
	}

	// 1. Vpc must exist.
	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			if err := r.updateStatusError(ctx, &resource, juneauv1alpha1.SecurityGroupReasonVpcNotFound,
				fmt.Sprintf("Vpc %q not found", resource.Spec.Vpc)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: securityGroupRequeueAfter}, nil
		}
		return ctrl.Result{}, err
	}

	// 2. Peer SG references must exist & be in the same Vpc. We tolerate
	// missing peers gracefully (drop them from the effective ruleset)
	// instead of refusing to reconcile, so that delete ordering does not
	// trap an SG into a permanently-degraded state.
	peerErrs := r.validatePeerRefs(ctx, &resource)

	// 3. GroupID allocation.
	gvk := schema.GroupVersionKind{
		Group:   juneauv1alpha1.GroupVersion.Group,
		Version: juneauv1alpha1.GroupVersion.Version,
		Kind:    "SecurityGroup",
	}
	claim, err := r.ensureGroupIDClaim(ctx, &resource, gvk)
	if err != nil {
		if updateErr := r.updateStatusError(ctx, &resource, juneauv1alpha1.SecurityGroupReasonAllocationFailed,
			fmt.Sprintf("failed to ensure groupID allocation claim: %v", err)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	groupID := resource.Status.GroupID
	if claim.Status.Phase == juneauv1alpha1.AllocationClaimPhaseAllocated && claim.Status.Value.Number > 0 {
		if claim.Status.Value.Number > uint64(^uint32(0)) {
			if err := r.updateStatusError(ctx, &resource, juneauv1alpha1.SecurityGroupReasonAllocationFailed,
				fmt.Sprintf("allocated groupID %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		groupID = uint32(claim.Status.Value.Number)
	}
	if groupID == 0 {
		if err := r.updateStatusPending(ctx, &resource, juneauv1alpha1.SecurityGroupReasonAllocating,
			"waiting for groupID allocation"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: securityGroupRequeueAfter}, nil
	}

	// 4. Ruleset projection + summary.
	summary := summarizeRules(&resource.Spec)
	rulesValid := len(peerErrs) == 0
	overBudget := summary.overBudgetMessage()

	// 5. Track attached NetworkInterfaces (observability only).
	attached, err := r.listAttachedInterfaces(ctx, &resource)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 6. Compute desired status and write.
	rulesetVersion := r.nextRulesetVersion(&resource, summary)

	rulesValidCondition := metav1.Condition{
		Type:    juneauv1alpha1.SecurityGroupConditionRulesValid,
		Status:  metav1.ConditionTrue,
		Reason:  juneauv1alpha1.SecurityGroupReasonReconcileSucceeded,
		Message: "",
	}
	readyCondition := metav1.Condition{
		Type:    juneauv1alpha1.SecurityGroupConditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  juneauv1alpha1.SecurityGroupReasonReconcileSucceeded,
		Message: "",
	}
	switch {
	case !rulesValid:
		rulesValidCondition.Status = metav1.ConditionFalse
		rulesValidCondition.Reason = juneauv1alpha1.SecurityGroupReasonPeerNotFound
		rulesValidCondition.Message = peerErrs[0]
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = juneauv1alpha1.SecurityGroupReasonRulesInvalid
		readyCondition.Message = peerErrs[0]
	case overBudget != "":
		rulesValidCondition.Status = metav1.ConditionFalse
		rulesValidCondition.Reason = juneauv1alpha1.SecurityGroupReasonRuleLimitExceeded
		rulesValidCondition.Message = overBudget
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = juneauv1alpha1.SecurityGroupReasonRuleLimitExceeded
		readyCondition.Message = overBudget
	}

	return ctrl.Result{}, r.updateStatus(ctx, &resource, securityGroupStatusUpdate{
		groupID:        groupID,
		summary:        summary,
		rulesetVersion: rulesetVersion,
		attached:       attached,
		conditions:     []metav1.Condition{rulesValidCondition, readyCondition},
	})
}

func (r *SecurityGroupReconciler) ensureGroupIDClaim(ctx context.Context, resource *juneauv1alpha1.SecurityGroup, gvk schema.GroupVersionKind) (*juneauv1alpha1.AllocationClaim, error) {
	claim := newAllocationClaim(allocationPoolSecurityGroupID, gvk, "", resource.Name, "status.groupID")
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(allocationPoolSecurityGroupID, gvk, "", resource.Name, "status.groupID").Spec
		return controllerutil.SetControllerReference(resource, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

// validatePeerRefs verifies that every securityGroupRef peer points to an
// existing SecurityGroup in the same Vpc. Returns a list of human-readable
// error strings (empty when all peers resolve).
func (r *SecurityGroupReconciler) validatePeerRefs(ctx context.Context, resource *juneauv1alpha1.SecurityGroup) []string {
	var errs []string
	check := func(direction string, idx int, peer juneauv1alpha1.SecurityGroupPeer) {
		if peer.SecurityGroupRef == nil {
			return
		}
		var peerSG juneauv1alpha1.SecurityGroup
		if err := r.Get(ctx, client.ObjectKey{Name: peer.SecurityGroupRef.Name}, &peerSG); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, fmt.Sprintf("%s rule [%d]: peer SecurityGroup %q not found",
					direction, idx, peer.SecurityGroupRef.Name))
				return
			}
			errs = append(errs, fmt.Sprintf("%s rule [%d]: peer lookup failed: %v",
				direction, idx, err))
			return
		}
		if peerSG.Spec.Vpc != resource.Spec.Vpc {
			errs = append(errs, fmt.Sprintf("%s rule [%d]: peer %q belongs to Vpc %q (expected %q)",
				direction, idx, peerSG.Name, peerSG.Spec.Vpc, resource.Spec.Vpc))
		}
	}

	for i, rule := range resource.Spec.Ingress {
		for _, peer := range rule.From {
			check("ingress", i, peer)
		}
	}
	if resource.Spec.Egress != nil {
		for i, rule := range *resource.Spec.Egress {
			for _, peer := range rule.To {
				check("egress", i, peer)
			}
		}
	}
	return errs
}

// securityGroupRuleSummary is everything the controller publishes about
// a spec's rules. It separates the two numbers that used to share the
// name "rule count": the rule count is what the user wrote, the entry
// count is what those rules cost in the data plane once they expand
// over peers and ports. Capacity is budgeted against the entry count
// alone. Mirrors the NetworkACL summary.
type securityGroupRuleSummary struct {
	ingressRuleCount  int32
	egressRuleCount   int32
	ingressEntryCount int32
	egressEntryCount  int32
	hasEgressRules    bool
}

// summarizeRules counts both rules and entries per direction and
// records whether the spec declared egress at all (nil → allow-all,
// non-nil → allow-list).
func summarizeRules(spec *juneauv1alpha1.SecurityGroupSpec) securityGroupRuleSummary {
	summary := securityGroupRuleSummary{
		ingressRuleCount:  int32(len(spec.Ingress)),
		ingressEntryCount: int32(juneauv1alpha1.SecurityGroupIngressEntryCount(spec.Ingress)),
	}
	if spec.Egress != nil {
		summary.hasEgressRules = true
		summary.egressRuleCount = int32(len(*spec.Egress))
		summary.egressEntryCount = int32(juneauv1alpha1.SecurityGroupEgressEntryCount(*spec.Egress))
	}
	return summary
}

// overBudgetMessage describes every direction whose entries do not fit
// SecurityGroupMaxEntriesPerDirection, or "" when the spec fits. The
// message names the direction, its entry count and the limit, and
// spells out how rules turn into entries: a single rule can blow the
// budget on its own, so the rule count alone explains nothing.
func (s securityGroupRuleSummary) overBudgetMessage() string {
	var over []string
	if s.ingressEntryCount > juneauv1alpha1.SecurityGroupMaxEntriesPerDirection {
		over = append(over, fmt.Sprintf("ingress rule count %d needs %d entries", s.ingressRuleCount, s.ingressEntryCount))
	}
	if s.egressEntryCount > juneauv1alpha1.SecurityGroupMaxEntriesPerDirection {
		over = append(over, fmt.Sprintf("egress rule count %d needs %d entries", s.egressRuleCount, s.egressEntryCount))
	}
	if len(over) == 0 {
		return ""
	}
	return fmt.Sprintf("%s, but a direction holds at most %d entries; a rule costs one entry per (peer, port) pair, so drop peers or ports or split the SecurityGroup",
		strings.Join(over, " and "), juneauv1alpha1.SecurityGroupMaxEntriesPerDirection)
}

// nextRulesetVersion returns the version to record in status. We bump on
// any observable summary change (rule counts, entry counts, egress mode,
// generation) so that daemons can detect "the ruleset I have differs
// from the published one" without a deep diff.
func (r *SecurityGroupReconciler) nextRulesetVersion(resource *juneauv1alpha1.SecurityGroup, summary securityGroupRuleSummary) uint64 {
	if securityGroupSummaryFromStatus(resource.Status) == summary &&
		resource.Status.ObservedGeneration == resource.Generation &&
		resource.Status.RulesetVersion > 0 {
		return resource.Status.RulesetVersion
	}
	return resource.Status.RulesetVersion + 1
}

// securityGroupSummaryFromStatus reads back the summary a previous
// reconcile published, so error and pending paths can rewrite status
// without inventing new counts.
func securityGroupSummaryFromStatus(status juneauv1alpha1.SecurityGroupStatus) securityGroupRuleSummary {
	return securityGroupRuleSummary{
		ingressRuleCount:  status.IngressRuleCount,
		egressRuleCount:   status.EgressRuleCount,
		ingressEntryCount: status.IngressEntryCount,
		egressEntryCount:  status.EgressEntryCount,
		hasEgressRules:    status.HasEgressRules,
	}
}

// listAttachedInterfaces enumerates NetworkInterfaces that name this SG.
// Sorted for deterministic status diffs.
func (r *SecurityGroupReconciler) listAttachedInterfaces(ctx context.Context, resource *juneauv1alpha1.SecurityGroup) ([]juneauv1alpha1.SecurityGroupAttachedInterface, error) {
	var ifaces juneauv1alpha1.NetworkInterfaceList
	if err := r.List(ctx, &ifaces); err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.SecurityGroupAttachedInterface, 0)
	for i := range ifaces.Items {
		iface := &ifaces.Items[i]
		for _, sg := range iface.Spec.SecurityGroups {
			if sg == resource.Name {
				out = append(out, juneauv1alpha1.SecurityGroupAttachedInterface{
					Namespace: iface.Namespace,
					Name:      iface.Name,
				})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

type securityGroupStatusUpdate struct {
	groupID        uint32
	summary        securityGroupRuleSummary
	rulesetVersion uint64
	attached       []juneauv1alpha1.SecurityGroupAttachedInterface
	conditions     []metav1.Condition
}

func (r *SecurityGroupReconciler) updateStatus(ctx context.Context, resource *juneauv1alpha1.SecurityGroup, u securityGroupStatusUpdate) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = resource.Generation
	updated.Status.GroupID = u.groupID
	updated.Status.IngressRuleCount = u.summary.ingressRuleCount
	updated.Status.EgressRuleCount = u.summary.egressRuleCount
	updated.Status.IngressEntryCount = u.summary.ingressEntryCount
	updated.Status.EgressEntryCount = u.summary.egressEntryCount
	updated.Status.HasEgressRules = u.summary.hasEgressRules
	updated.Status.RulesetVersion = u.rulesetVersion
	updated.Status.AttachedInterfaces = u.attached

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

func (r *SecurityGroupReconciler) updateStatusError(ctx context.Context, resource *juneauv1alpha1.SecurityGroup, reason, message string) error {
	rulesValid := metav1.Condition{
		Type:    juneauv1alpha1.SecurityGroupConditionRulesValid,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	}
	ready := metav1.Condition{
		Type:    juneauv1alpha1.SecurityGroupConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	}
	return r.updateStatus(ctx, resource, securityGroupStatusUpdate{
		groupID:        resource.Status.GroupID,
		summary:        securityGroupSummaryFromStatus(resource.Status),
		rulesetVersion: resource.Status.RulesetVersion,
		attached:       resource.Status.AttachedInterfaces,
		conditions:     []metav1.Condition{rulesValid, ready},
	})
}

func (r *SecurityGroupReconciler) updateStatusPending(ctx context.Context, resource *juneauv1alpha1.SecurityGroup, reason, message string) error {
	ready := metav1.Condition{
		Type:    juneauv1alpha1.SecurityGroupConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	}
	return r.updateStatus(ctx, resource, securityGroupStatusUpdate{
		groupID:        resource.Status.GroupID,
		summary:        securityGroupSummaryFromStatus(resource.Status),
		rulesetVersion: resource.Status.RulesetVersion,
		attached:       resource.Status.AttachedInterfaces,
		conditions:     []metav1.Condition{ready},
	})
}

// SetupWithManager wires informers. Peer-cross-references mean a SG needs
// to be re-evaluated whenever any other SG in the same Vpc changes
// (membership / deletion); we fan out from peer changes.
func (r *SecurityGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.SecurityGroup{}).
		Watches(&juneauv1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToSG)).
		Watches(&juneauv1alpha1.SecurityGroup{}, handler.EnqueueRequestsFromMapFunc(r.mapPeerSGToSG)).
		Watches(&juneauv1alpha1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.mapInterfaceToSGs)).
		Named("securitygroup").
		Complete(r)
}

func (r *SecurityGroupReconciler) mapClaimToSG(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "SecurityGroup" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

func (r *SecurityGroupReconciler) mapPeerSGToSG(ctx context.Context, obj client.Object) []reconcile.Request {
	peerSG, ok := obj.(*juneauv1alpha1.SecurityGroup)
	if !ok {
		return nil
	}
	// Re-enqueue every SG in the same Vpc so they reconverge their
	// status.AttachedInterfaces / rule validity.
	var list juneauv1alpha1.SecurityGroupList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, sg := range list.Items {
		if sg.Name == peerSG.Name {
			continue
		}
		if sg.Spec.Vpc != peerSG.Spec.Vpc {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: sg.Name}})
	}
	return reqs
}

func (r *SecurityGroupReconciler) mapInterfaceToSGs(_ context.Context, obj client.Object) []reconcile.Request {
	iface, ok := obj.(*juneauv1alpha1.NetworkInterface)
	if !ok {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(iface.Spec.SecurityGroups))
	for _, sg := range iface.Spec.SecurityGroups {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: sg}})
	}
	return reqs
}

// ParseCIDR is a small re-export: webhook validation uses it too.
//
// Returning the prefix length rather than the netip.Prefix simplifies the
// data-plane writer signature, which only needs (addr, prefixlen).
func ParseCIDR(s string) (netip.Addr, int, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if !prefix.Addr().Is4() {
		return netip.Addr{}, 0, fmt.Errorf("only IPv4 CIDRs are supported: %s", s)
	}
	return prefix.Addr(), prefix.Bits(), nil
}

// SecurityGroupKey returns the key used to look up SGs by name. The
// helper exists for parity with how other controllers compose keys.
func SecurityGroupKey(name string) types.NamespacedName {
	return types.NamespacedName{Name: name}
}
