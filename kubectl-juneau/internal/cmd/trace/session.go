package trace

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// sessionLifecycle wraps create + delete of the TraceSession CRD so
// the Run loop can keep its own goroutines focused on event flow.
//
// Cleanup is mandatory: callers MUST defer Cleanup so a normal exit,
// a Ctrl-C, or a panic still removes the CRD. Daemons additionally
// rely on spec.expiresAt to evict orphans if Cleanup is somehow
// skipped.
type sessionLifecycle struct {
	cl     client.Client
	name   string
	keep   bool
	cancel context.CancelFunc
}

// createSession constructs the TraceSession from resolved state and
// posts it to the API server. The returned lifecycle handle owns
// cleanup on exit.
func (o *Options) createSession(ctx context.Context, cl client.Client, r *resolved) (*sessionLifecycle, *juneauv1alpha1.TraceSession, error) {
	expiresAt := metav1.NewTime(time.Now().Add(o.TTL))
	ts := &juneauv1alpha1.TraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: traceSessionName(r.traceID),
			Labels: map[string]string{
				"juneau.loutres.me/created-by": "kubectl-juneau",
				"juneau.loutres.me/trace-id":   strconv.FormatUint(uint64(r.traceID), 10),
			},
		},
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID:       r.traceID,
			ExpiresAt:     expiresAt,
			Mode:          o.crdMode(),
			Capture:       o.crdCapture(),
			Source:        o.crdSourceEndpoint(r),
			Destination:   o.crdDestinationEndpoint(r),
			InitialTuples: r.initialTuples,
		},
	}
	if err := cl.Create(ctx, ts); err != nil {
		return nil, nil, fmt.Errorf("create TraceSession: %w", err)
	}
	return &sessionLifecycle{cl: cl, name: ts.Name, keep: o.KeepSession}, ts, nil
}

// Cleanup removes the TraceSession unless --keep-session was set.
// Idempotent.
func (s *sessionLifecycle) Cleanup() error {
	if s == nil {
		return fmt.Errorf("trace: cleanup called on nil lifecycle")
	}
	if s.keep {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ts := &juneauv1alpha1.TraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: s.name},
	}
	if err := s.cl.Delete(ctx, ts); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete TraceSession %s: %w", s.name, err)
	}
	return nil
}

// WaitForCleanupAck polls the CRD until daemons have removed
// themselves from status.observedNodes (i.e. each daemon
// acknowledged the delete and tore down BPF state). Best-effort:
// returns once the timeout expires even if some daemons are
// unresponsive — orphan state is still bounded by spec.expiresAt.
func (s *sessionLifecycle) WaitForCleanupAck(ctx context.Context, timeout time.Duration) error {
	if s == nil || s.keep {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var ts juneauv1alpha1.TraceSession
		err := s.cl.Get(ctx, types.NamespacedName{Name: s.name}, &ts)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(ts.Status.ObservedNodes) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("trace: timed out waiting for daemons to release session state")
}

func traceSessionName(traceID uint32) string {
	return fmt.Sprintf("trace-%s-%08x", time.Now().UTC().Format("20060102-150405"), traceID)
}

func (o *Options) crdSourceEndpoint(r *resolved) juneauv1alpha1.TraceEndpoint {
	ep := juneauv1alpha1.TraceEndpoint{}
	if r.source.pod != nil {
		ep.PodRef = &juneauv1alpha1.TracePodReference{
			Namespace: r.source.pod.Namespace,
			Name:      r.source.pod.Name,
		}
	} else if r.source.ip.IsValid() {
		ep.IP = r.source.ip.String()
	}
	return ep
}

func (o *Options) crdDestinationEndpoint(r *resolved) juneauv1alpha1.TraceEndpoint {
	ep := juneauv1alpha1.TraceEndpoint{
		Protocol: o.crdProtocol(),
		Port:     o.Port,
	}
	switch {
	case r.destination.pod != nil:
		ep.PodRef = &juneauv1alpha1.TracePodReference{
			Namespace: r.destination.pod.Namespace,
			Name:      r.destination.pod.Name,
		}
	case r.destination.service != nil:
		ep.ServiceRef = &juneauv1alpha1.TraceServiceReference{
			Namespace: r.destination.service.Namespace,
			Name:      r.destination.service.Name,
		}
	case r.destination.ip.IsValid():
		ep.IP = r.destination.ip.String()
	}
	return ep
}
