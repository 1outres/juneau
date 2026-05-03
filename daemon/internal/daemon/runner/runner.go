package runner

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// SingletonKey is used as the enqueue key for reconcilers whose desired state
// is a function of cluster-wide inputs (e.g. the BGP address pool set).
const SingletonKey = "__singleton__"

// defaultReconcileTimeout bounds how long a single Reconcile call may run.
const defaultReconcileTimeout = 30 * time.Second

// Reconciler is the minimal contract a work-queue driven reconciler must
// implement. Name is used for log prefixes.
type Reconciler interface {
	Name() string
	Reconcile(ctx context.Context, key string) error
}

// Runner drives a Reconciler: it owns a workqueue, registers informer
// handlers that enqueue keys, and runs worker goroutines.
type Runner struct {
	reconciler Reconciler
	queue      workqueue.TypedRateLimitingInterface[string]
	regs       []handlerReg
	timeout    time.Duration
}

type handlerReg struct {
	informer cache.Informer
	reg      toolscache.ResourceEventHandlerRegistration
}

// New constructs a Runner around a Reconciler with the default rate-limited
// workqueue.
func New(r Reconciler) *Runner {
	return &Runner{
		reconciler: r,
		queue: workqueue.NewTypedRateLimitingQueue(
			workqueue.DefaultTypedControllerRateLimiter[string](),
		),
		timeout: defaultReconcileTimeout,
	}
}

// Watch registers an informer so that every event enqueues a single key
// derived from the event object. keyFunc may return ok=false to skip.
func (r *Runner) Watch(informer cache.Informer, keyFunc func(obj any) (string, bool)) error {
	return r.watch(informer, func(obj any) []string {
		key, ok := keyFunc(obj)
		if !ok {
			return nil
		}
		return []string{key}
	})
}

// WatchFanOut registers an informer so that every event enqueues zero or
// more keys. Use this when a change to one resource triggers reconciliation
// of many primary objects (e.g. a Subnet change re-enqueues every RouteTable).
func (r *Runner) WatchFanOut(informer cache.Informer, keysFunc func(obj any) []string) error {
	return r.watch(informer, keysFunc)
}

func (r *Runner) watch(informer cache.Informer, keysFunc func(obj any) []string) error {
	enqueue := func(obj any) {
		for _, key := range keysFunc(obj) {
			r.queue.Add(key)
		}
	}
	reg, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    enqueue,
		UpdateFunc: func(_, newObj any) { enqueue(newObj) },
		DeleteFunc: enqueue,
	})
	if err != nil {
		return err
	}
	r.regs = append(r.regs, handlerReg{informer, reg})
	return nil
}

// Enqueue adds a key directly to the work queue. Use for bootstrapping.
func (r *Runner) Enqueue(key string) { r.queue.Add(key) }

// Start launches `workers` goroutines that process the queue until ctx is
// cancelled or Stop is called.
func (r *Runner) Start(ctx context.Context, workers int) {
	for range workers {
		go func() {
			for r.processNext(ctx) {
			}
		}()
	}
	go func() {
		<-ctx.Done()
		r.queue.ShutDown()
	}()
}

// Stop removes all registered event handlers and shuts the queue down.
func (r *Runner) Stop() error {
	r.queue.ShutDown()
	var errs []error
	for _, reg := range r.regs {
		if err := reg.informer.RemoveEventHandler(reg.reg); err != nil {
			errs = append(errs, err)
		}
	}
	r.regs = nil
	return errors.Join(errs...)
}

func (r *Runner) processNext(ctx context.Context) bool {
	key, shutdown := r.queue.Get()
	if shutdown {
		return false
	}
	defer r.queue.Done(key)

	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if err := r.reconciler.Reconcile(cctx, key); err != nil {
		zap.S().Errorf("%s: reconcile %q failed: %v", r.reconciler.Name(), key, err)
		r.queue.AddRateLimited(key)
		return true
	}
	r.queue.Forget(key)
	return true
}

// MetaNamespaceKey is a keyFunc for Watch: returns "namespace/name" for
// the object, transparently handling tombstones.
func MetaNamespaceKey(obj any) (string, bool) {
	key, err := toolscache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		return "", false
	}
	return key, true
}

// ConstantKey returns a keyFunc that always enqueues the same key regardless
// of the triggering object. Useful for singleton reconcilers.
func ConstantKey(key string) func(obj any) (string, bool) {
	return func(any) (string, bool) { return key, true }
}
