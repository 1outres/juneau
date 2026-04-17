package reconcile

import (
	"context"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Func func(ctx context.Context, nodeName string, cl client.Client) error

type Runner struct {
	nodeName  string
	client    client.Client
	reconcile Func

	debounce time.Duration

	queue     workqueue.TypedRateLimitingInterface[string]
	triggerCh chan struct{}
}

func NewRunner(nodeName string, cl client.Client, debounce time.Duration, reconcile Func) *Runner {
	return &Runner{
		nodeName:  nodeName,
		client:    cl,
		reconcile: reconcile,
		debounce:  debounce,
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		triggerCh: make(chan struct{}, 1),
	}
}

func (r *Runner) Trigger() {
	select {
	case r.triggerCh <- struct{}{}:
	default:
	}
}

func (r *Runner) Start(ctx context.Context) error {
	defer r.queue.ShutDown()

	go r.debounceLoop(ctx)
	r.workerLoop(ctx)

	return nil
}

func (r *Runner) debounceLoop(ctx context.Context) {
	const key = "global"

	var timer *time.Timer
	var timerC <-chan time.Time

	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
		timerC = nil
	}

	for {
		select {
		case <-ctx.Done():
			stopTimer()
			return
		case <-r.triggerCh:
			stopTimer()
			timer = time.NewTimer(r.debounce)
			timerC = timer.C
		case <-timerC:
			stopTimer()
			r.queue.Add(key)
		}
	}
}

func (r *Runner) workerLoop(ctx context.Context) {
	const key = "global"

	for {
		item, shutdown := r.queue.Get()
		if shutdown {
			return
		}

		func() {
			defer r.queue.Done(item)

			if item != key {
				r.queue.Forget(item)
				return
			}

			if err := r.reconcile(ctx, r.nodeName, r.client); err != nil {
				zap.S().Warnw("reconcile failed", "nodeName", r.nodeName, "error", err)
				r.queue.AddRateLimited(key)
				return
			}

			r.queue.Forget(item)
		}()
	}
}
