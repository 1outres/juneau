package trace

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reconciler watches TraceSession CRDs and projects them into BPF
// state via Store. It also patches TraceSession.status to mark this
// node as observing.
//
// Concurrency: multiple sessions are reconciled by independent
// workqueue items; Store serialises BPF writes internally. Status
// patches are idempotent — if a node is already listed in
// observedNodes the patch is skipped.
// storeIface narrows *Store to the methods the Reconciler needs so
// tests can substitute a fake.
type storeIface interface {
	Apply(SessionSpec) error
	Delete(traceID uint32) error
}

type Reconciler struct {
	client   client.Client
	store    storeIface
	nodeName string

	// idByName memoises the most recent traceID we observed for each
	// TraceSession name. The CRD object is gone by the time NotFound is
	// delivered, so we cannot recover the traceID from spec — we have
	// to remember it here. Used by deleteByName to target only the
	// removed session instead of tearing down every active trace.
	mu       sync.Mutex
	idByName map[string]uint32
}

// NewReconciler wires the dependencies. The same instance is used by
// the daemon's Runner and shares Store with the ringbuf reader.
func NewReconciler(cl client.Client, store *Store, nodeName string) *Reconciler {
	return &Reconciler{
		client:   cl,
		store:    store,
		nodeName: nodeName,
		idByName: make(map[string]uint32),
	}
}

// Name implements runner.Reconciler.
func (r *Reconciler) Name() string { return "tracesession" }

// Reconcile implements runner.Reconciler. The runner's keyFunc is
// MetaNamespaceKey, but TraceSession is cluster-scoped so the key is
// just the resource name.
func (r *Reconciler) Reconcile(ctx context.Context, key string) error {
	name := strings.TrimPrefix(key, "/")
	var ts juneauv1alpha1.TraceSession
	err := r.client.Get(ctx, types.NamespacedName{Name: name}, &ts)
	if apierrors.IsNotFound(err) {
		// kubectl deleted the CRD or it was finalized — drop our
		// dataplane state. We rely on the lookup-by-name on the next
		// `Apply` to backfill the trace_id, since the CRD object is
		// gone by the time we receive the delete event.
		return r.deleteByName(name)
	}
	if err != nil {
		return fmt.Errorf("get TraceSession %q: %w", name, err)
	}

	if !ts.DeletionTimestamp.IsZero() {
		return r.deleteSpec(ctx, &ts)
	}
	if ts.Spec.ExpiresAt.Time.Before(time.Now()) {
		// Past expiry — treat as deleted on this node.
		return r.deleteSpec(ctx, &ts)
	}

	spec, err := buildSessionSpec(&ts)
	if err != nil {
		return fmt.Errorf("build session %q: %w", name, err)
	}
	if err := r.store.Apply(spec); err != nil {
		return fmt.Errorf("apply session %q: %w", name, err)
	}
	r.rememberID(name, spec.TraceID)
	if err := r.markObserved(ctx, &ts); err != nil {
		zap.S().Warnw("trace: status patch failed", "name", name, "err", err)
	}
	return nil
}

func (r *Reconciler) deleteSpec(ctx context.Context, ts *juneauv1alpha1.TraceSession) error {
	if err := r.store.Delete(ts.Spec.TraceID); err != nil {
		return err
	}
	r.forgetID(ts.Name)
	return r.markUnobserved(ctx, ts)
}

func (r *Reconciler) deleteByName(name string) error {
	id, ok := r.takeID(name)
	if !ok {
		// Either we never applied this session on this node, or the
		// daemon restarted between Apply and the delete event. The
		// store's GC tick reaps stale state by expiresAt, so dropping
		// here is safe and avoids tearing down peer sessions.
		return nil
	}
	if err := r.store.Delete(id); err != nil {
		zap.S().Warnw("trace: delete-by-name failed", "name", name, "traceID", id, "err", err)
		return err
	}
	return nil
}

func (r *Reconciler) rememberID(name string, id uint32) {
	r.mu.Lock()
	r.idByName[name] = id
	r.mu.Unlock()
}

func (r *Reconciler) forgetID(name string) {
	r.mu.Lock()
	delete(r.idByName, name)
	r.mu.Unlock()
}

func (r *Reconciler) takeID(name string) (uint32, bool) {
	r.mu.Lock()
	id, ok := r.idByName[name]
	if ok {
		delete(r.idByName, name)
	}
	r.mu.Unlock()
	return id, ok
}

// markObserved appends this node to status.observedNodes and bumps
// LastObservedAt. Uses a server-side patch so concurrent updates from
// other daemons do not collide.
func (r *Reconciler) markObserved(ctx context.Context, ts *juneauv1alpha1.TraceSession) error {
	if r.nodeName == "" {
		return nil
	}
	already := slices.Contains(ts.Status.ObservedNodes, r.nodeName)
	now := metav1.Now()
	if already && ts.Status.Phase == juneauv1alpha1.TraceSessionPhaseActive {
		return nil
	}
	patch := client.MergeFrom(ts.DeepCopy())
	if !already {
		ts.Status.ObservedNodes = append(ts.Status.ObservedNodes, r.nodeName)
	}
	ts.Status.LastObservedAt = &now
	ts.Status.Phase = juneauv1alpha1.TraceSessionPhaseActive
	return r.client.Status().Patch(ctx, ts, patch)
}

func (r *Reconciler) markUnobserved(ctx context.Context, ts *juneauv1alpha1.TraceSession) error {
	if r.nodeName == "" {
		return nil
	}
	if !slices.Contains(ts.Status.ObservedNodes, r.nodeName) {
		return nil
	}
	patch := client.MergeFrom(ts.DeepCopy())
	ts.Status.ObservedNodes = slices.DeleteFunc(ts.Status.ObservedNodes, func(s string) bool {
		return s == r.nodeName
	})
	if err := r.client.Status().Patch(ctx, ts, patch); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// buildSessionSpec translates a TraceSession CRD into the daemon-side
// SessionSpec. Errors here are admission failures the webhook should
// have caught, but we re-validate at the daemon boundary so a
// rogue / bypassed object cannot corrupt BPF state.
func buildSessionSpec(ts *juneauv1alpha1.TraceSession) (SessionSpec, error) {
	tuples := make([]Tuple, 0, len(ts.Spec.InitialTuples))
	for i := range ts.Spec.InitialTuples {
		t, err := tupleFromCRD(&ts.Spec.InitialTuples[i])
		if err != nil {
			return SessionSpec{}, fmt.Errorf("tuple[%d]: %w", i, err)
		}
		tuples = append(tuples, t)
	}
	mode := uint8(0)
	if ts.Spec.Mode == juneauv1alpha1.TraceModeActiveProbe {
		mode = 1
	}
	return SessionSpec{
		TraceID:      ts.Spec.TraceID,
		Generation:   ts.Generation,
		ExpiresAt:    ts.Spec.ExpiresAt.Time,
		CaptureFlags: captureFlags(ts.Spec.Capture),
		Level:        captureLevel(ts.Spec.Capture.Level),
		Mode:         mode,
		Tuples:       tuples,
	}, nil
}

func tupleFromCRD(t *juneauv1alpha1.TraceTuple) (Tuple, error) {
	src, err := parseIPv4(t.SrcIP)
	if err != nil {
		return Tuple{}, fmt.Errorf("srcIP: %w", err)
	}
	dst, err := parseIPv4(t.DstIP)
	if err != nil {
		return Tuple{}, fmt.Errorf("dstIP: %w", err)
	}
	scope := ScopeHost
	if t.Scope == juneauv1alpha1.TraceTupleScopeVPC {
		scope = ScopeVPC
	}
	return Tuple{
		Key: TupleKey{
			Scope:    scope,
			Protocol: ipProto(t.Protocol),
			VPCID:    t.VPCID,
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  uint16(t.SrcPort),
			DstPort:  uint16(t.DstPort),
		},
		Direction: directionFromCRD(t.Direction),
	}, nil
}

// directionFromCRD maps the CRD leg enum to the BPF value. Empty
// defaults to Request — the apiserver fills the default, but daemons
// re-validate at their boundary and must not treat an unset field as
// an unknown leg.
func directionFromCRD(d juneauv1alpha1.TraceTupleDirection) Direction {
	if d == juneauv1alpha1.TraceTupleDirectionReply {
		return DirReply
	}
	return DirRequest
}

func parseIPv4(s string) ([4]byte, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return [4]byte{}, err
	}
	if !addr.Is4() {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			return [4]byte{}, fmt.Errorf("not an IPv4 address: %q", s)
		}
		var out [4]byte
		copy(out[:], ip)
		return out, nil
	}
	return addr.As4(), nil
}

func captureFlags(c juneauv1alpha1.TraceCaptureConfig) CaptureFlag {
	var f CaptureFlag
	if c.IncludePacketMeta {
		f |= CapturePacketMeta
	}
	if c.IncludeMapMiss {
		f |= CaptureMapMiss
	}
	if c.IncludePolicy {
		f |= CapturePolicy
	}
	if c.IncludeNAT {
		f |= CaptureNAT
	}
	return f
}

func captureLevel(l juneauv1alpha1.TraceCaptureLevel) CaptureLevel {
	switch l {
	case juneauv1alpha1.TraceCaptureLevelSummary:
		return LevelSummary
	case juneauv1alpha1.TraceCaptureLevelVerbose:
		return LevelVerbose
	case juneauv1alpha1.TraceCaptureLevelDecision:
		return LevelDecision
	default:
		return LevelDecision
	}
}

func ipProto(p juneauv1alpha1.TraceProtocol) uint8 {
	switch p {
	case juneauv1alpha1.TraceProtocolTCP:
		return 6 // IPPROTO_TCP
	case juneauv1alpha1.TraceProtocolUDP:
		return 17 // IPPROTO_UDP
	case juneauv1alpha1.TraceProtocolICMP:
		return 1 // IPPROTO_ICMP
	}
	return 0
}
