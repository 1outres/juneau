package reconciler

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policy"
)

// NetworkACL keeps the BPF acl_meta_map / acl_rule_table tables in
// sync with NetworkACL CRDs. Mirrors the SecurityGroup reconciler in
// shape; the differences are:
//
//   - ACLs do not have peer-SG references, so there is no nameToID
//     resolver cache and no Vpc-wide fan-out for peer changes. ACL
//     evaluation is purely CIDR-based.
//   - Rule expansion sorts by (direction, priority) so the BPF
//     evaluator can scan in priority order. ACLStore writes the inner
//     map slot-for-slot in that order.
//   - Snapshot bookkeeping tracks aclID per ACL name so a delete event
//     after the API object is gone can still reach the right BPF
//     entries.
type NetworkACL struct {
	client client.Client
	store  *policy.ACLStore

	// snapshots lets a name-driven Reconcile(NotFound → delete) pair
	// reach the right aclID after status.aclID is no longer
	// observable.
	snapshots map[string]uint32
}

func NewNetworkACL(cl client.Client, store *policy.ACLStore) *NetworkACL {
	return &NetworkACL{
		client:    cl,
		store:     store,
		snapshots: make(map[string]uint32),
	}
}

func (r *NetworkACL) Name() string { return "networkacl" }

func (r *NetworkACL) Reconcile(ctx context.Context, key string) error {
	var acl juneauv1alpha1.NetworkACL
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &acl)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	return r.upsert(&acl)
}

func (r *NetworkACL) upsert(acl *juneauv1alpha1.NetworkACL) error {
	if acl.Status.ACLID == 0 {
		// Controller has not allocated an ACLID yet; later events
		// will drive the actual write once the AllocationClaim
		// resolves.
		return nil
	}

	rs, err := policy.ExpandNetworkACL(acl)
	if err != nil {
		return fmt.Errorf("expand acl %s: %w", acl.Name, err)
	}

	zap.S().Infow("networkacl: applying",
		"name", acl.Name,
		"aclID", rs.GroupID,
		"ingress", rs.IngressCount,
		"egress", rs.EgressCount,
		"hasIngress", rs.HasIngressRules,
		"hasEgress", rs.HasEgressRules)
	if err := r.store.Apply(rs); err != nil && !errors.Is(err, policy.ErrACLRuleLimitExceeded) {
		return err
	}

	r.snapshots[acl.Name] = acl.Status.ACLID
	return nil
}

func (r *NetworkACL) delete(name string) error {
	aclID, ok := r.snapshots[name]
	delete(r.snapshots, name)
	if !ok || aclID == 0 {
		return nil
	}
	return r.store.Delete(aclID)
}
