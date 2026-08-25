package reconciler

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policy"
)

// SecurityGroup keeps the BPF SG rule + meta tables in sync with
// SecurityGroup objects. The reconciler delegates rule expansion to
// the policy package; it itself owns the per-SG snapshot bookkeeping
// and the {SG name → GroupID} cache used to resolve from-SG / to-SG
// peer references.
//
// The reconciler is informer-driven: every SG event enqueues the SG by
// name, and every SG event also fan-outs to other SGs in the same Vpc
// (so a previously-unknown peer SG re-resolves).
type SecurityGroup struct {
	client client.Client
	store  *policy.SGStore

	mu sync.Mutex
	// nameToID is the resolver cache: SG name → groupID. Updated on
	// upsert / delete. Used by ExpandSecurityGroup as the PeerResolver.
	nameToID map[string]uint32
	// snapshots tracks groupID per SG name so a later delete can reach
	// the right BPF entry even after the API object is gone.
	snapshots map[string]uint32
}

func NewSecurityGroup(cl client.Client, store *policy.SGStore) *SecurityGroup {
	return &SecurityGroup{
		client:    cl,
		store:     store,
		nameToID:  make(map[string]uint32),
		snapshots: make(map[string]uint32),
	}
}

func (r *SecurityGroup) Name() string { return "securitygroup" }

func (r *SecurityGroup) Reconcile(ctx context.Context, key string) error {
	var sg juneauv1alpha1.SecurityGroup
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &sg)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	return r.upsert(ctx, &sg)
}

func (r *SecurityGroup) upsert(_ context.Context, sg *juneauv1alpha1.SecurityGroup) error {
	if sg.Status.GroupID == 0 {
		// Controller has not allocated a GroupID yet. Track only what
		// we know and let a later event drive the actual write.
		return nil
	}

	rs, err := policy.ExpandSecurityGroup(sg, r.resolverSnapshot())
	if err != nil {
		return fmt.Errorf("expand sg %s: %w", sg.Name, err)
	}

	zap.S().Infow("securitygroup: applying",
		"name", sg.Name,
		"groupID", rs.GroupID,
		"ingress", len(rs.Ingress),
		"egress", len(rs.Egress),
		"hasEgress", rs.HasEgressRules)
	if err := r.store.Apply(rs); err != nil {
		overCapacity := policy.CapacityErrorsFrom(err)
		if len(overCapacity) == 0 {
			return err
		}
		// A spec that does not fit never starts fitting, so returning
		// the error would only make the runner requeue this key behind
		// a rate limiter forever. Apply already installed the
		// direction fail-closed, so the data plane is safe; the
		// controller owns telling the user through status.
		for _, capacity := range overCapacity {
			zap.S().Errorw("securitygroup: direction over capacity, installed fail-closed",
				"name", sg.Name,
				"groupID", capacity.ID,
				"direction", capacity.Direction.String(),
				"entries", capacity.Entries,
				"limit", capacity.Limit)
		}
	}

	r.mu.Lock()
	r.nameToID[sg.Name] = sg.Status.GroupID
	r.snapshots[sg.Name] = sg.Status.GroupID
	r.mu.Unlock()
	return nil
}

func (r *SecurityGroup) delete(name string) error {
	r.mu.Lock()
	gid := r.snapshots[name]
	delete(r.snapshots, name)
	delete(r.nameToID, name)
	r.mu.Unlock()
	if gid == 0 {
		return nil
	}
	return r.store.Delete(gid)
}

// resolverSnapshot returns a stable copy of the name→ID cache for use
// during expand. We snapshot under the lock so concurrent mutations of
// nameToID do not race with the expansion.
func (r *SecurityGroup) resolverSnapshot() policy.MapPeerResolver {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(policy.MapPeerResolver, len(r.nameToID))
	for k, v := range r.nameToID {
		out[k] = v
	}
	return out
}

// FanOutVpcPeers re-enqueues every SG in the same Vpc as the changed
// SG so that newly-resolvable peer references propagate. The signature
// matches Runner.WatchFanOut.
func (r *SecurityGroup) FanOutVpcPeers(obj any) []string {
	sg, ok := obj.(*juneauv1alpha1.SecurityGroup)
	if !ok {
		return nil
	}
	var list juneauv1alpha1.SecurityGroupList
	if err := r.client.List(context.Background(), &list); err != nil {
		return nil
	}
	var keys []string
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == sg.Name {
			continue
		}
		if other.Spec.Vpc != sg.Spec.Vpc {
			continue
		}
		keys = append(keys, other.Name)
	}
	return keys
}
