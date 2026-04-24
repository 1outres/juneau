package nodestate

import (
	"sort"
	"time"

	"github.com/1outres/juneau/bgp-speaker/internal/bmp"
	"github.com/1outres/juneau/bgp-speaker/internal/peerindex"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Inputs carries the signals the Builder cannot derive on its own.
// Callers assemble this from the reconciler / bird process state.
type Inputs struct {
	BirdRunning    bool
	Advertisements []Advertisement
	Errors         []ResourceError
}

type Advertisement struct {
	AddressPool  string
	Prefixes     []string
	LastSyncedAt time.Time
}

type ResourceError struct {
	ResourceKind string
	ResourceName string
	Message      string
	LastSeen     time.Time
}

type Option func(*Builder)

func WithNowFunc(fn func() time.Time) Option {
	return func(b *Builder) { b.nowFn = fn }
}

const (
	ConditionReady        = "Ready"
	ConditionBirdRunning  = "BirdRunning"
	ConditionBMPConnected = "BMPConnected"
)

type Builder struct {
	nodeName string
	tracker  *bmp.Tracker
	index    *peerindex.PeerIndex
	nowFn    func() time.Time
}

func NewBuilder(nodeName string, tracker *bmp.Tracker, index *peerindex.PeerIndex, opts ...Option) *Builder {
	b := &Builder{
		nodeName: nodeName,
		tracker:  tracker,
		index:    index,
		nowFn:    time.Now,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

func (b *Builder) Build(in Inputs) juneauv1alpha1.BGPNodeStateStatus {
	now := metav1.NewTime(b.nowFn())
	return juneauv1alpha1.BGPNodeStateStatus{
		Heartbeat:      &now,
		BGPSessions:    b.buildSessions(),
		Advertisements: buildAdvertisements(in.Advertisements),
		Conditions:     b.buildConditions(in, now),
		Errors:         buildErrors(in.Errors),
	}
}

func buildErrors(errs []ResourceError) []juneauv1alpha1.BGPNodeStateError {
	out := make([]juneauv1alpha1.BGPNodeStateError, 0, len(errs))
	for _, e := range errs {
		entry := juneauv1alpha1.BGPNodeStateError{
			ResourceKind: e.ResourceKind,
			ResourceName: e.ResourceName,
			Message:      e.Message,
		}
		if !e.LastSeen.IsZero() {
			t := metav1.NewTime(e.LastSeen)
			entry.LastSeen = &t
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ResourceKind != out[j].ResourceKind {
			return out[i].ResourceKind < out[j].ResourceKind
		}
		return out[i].ResourceName < out[j].ResourceName
	})
	return out
}

func (b *Builder) buildConditions(in Inputs, now metav1.Time) []metav1.Condition {
	bmpConnected := b.tracker.Connected()

	bird := metav1.Condition{
		Type:               ConditionBirdRunning,
		LastTransitionTime: now,
	}
	if in.BirdRunning {
		bird.Status = metav1.ConditionTrue
		bird.Reason = "Running"
		bird.Message = "bird process is running"
	} else {
		bird.Status = metav1.ConditionFalse
		bird.Reason = "NotRunning"
		bird.Message = "bird process is not running"
	}

	conn := metav1.Condition{
		Type:               ConditionBMPConnected,
		LastTransitionTime: now,
	}
	if bmpConnected {
		conn.Status = metav1.ConditionTrue
		conn.Reason = "Connected"
		conn.Message = "BMP station has an active bird connection"
	} else {
		conn.Status = metav1.ConditionFalse
		conn.Reason = "Disconnected"
		conn.Message = "no bird is connected to the BMP station"
	}

	ready := metav1.Condition{
		Type:               ConditionReady,
		LastTransitionTime: now,
	}
	switch {
	case !in.BirdRunning:
		ready.Status = metav1.ConditionFalse
		ready.Reason = "BirdNotRunning"
		ready.Message = bird.Message
	case !bmpConnected:
		ready.Status = metav1.ConditionFalse
		ready.Reason = "BMPNotConnected"
		ready.Message = conn.Message
	default:
		ready.Status = metav1.ConditionTrue
		ready.Reason = "Healthy"
		ready.Message = "bird running and BMP connected"
	}

	return []metav1.Condition{ready, bird, conn}
}

func (b *Builder) buildSessions() []juneauv1alpha1.BGPNodeStateSession {
	sessions := b.tracker.Snapshot()
	out := make([]juneauv1alpha1.BGPNodeStateSession, 0, len(sessions))
	for _, s := range sessions {
		name, _ := b.index.Name(s.PeerAddress)
		entry := juneauv1alpha1.BGPNodeStateSession{
			PeerAddress: s.PeerAddress,
			PeerName:    name,
			State:       string(s.State),
			LastError:   s.LastError,
		}
		if !s.UpSince.IsZero() {
			t := metav1.NewTime(s.UpSince)
			entry.UpSince = &t
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeerAddress < out[j].PeerAddress })
	return out
}

func buildAdvertisements(ads []Advertisement) []juneauv1alpha1.BGPNodeStateAdvertisement {
	out := make([]juneauv1alpha1.BGPNodeStateAdvertisement, 0, len(ads))
	for _, a := range ads {
		prefixes := append([]string(nil), a.Prefixes...)
		sort.Strings(prefixes)
		entry := juneauv1alpha1.BGPNodeStateAdvertisement{
			AddressPool: a.AddressPool,
			Prefixes:    prefixes,
		}
		if !a.LastSyncedAt.IsZero() {
			t := metav1.NewTime(a.LastSyncedAt)
			entry.LastSyncedAt = &t
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AddressPool < out[j].AddressPool })
	return out
}
