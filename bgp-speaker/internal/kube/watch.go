package kube

import (
	"context"
	"fmt"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Invalidator struct {
	ch chan struct{}
}

func NewInvalidator() *Invalidator {
	return &Invalidator{ch: make(chan struct{}, 1)}
}

func (i *Invalidator) C() <-chan struct{} {
	return i.ch
}

func (i *Invalidator) Notify() {
	select {
	case i.ch <- struct{}{}:
	default:
	}
}

func (i *Invalidator) RegisterHandlers(ctx context.Context, c cache.Cache) error {
	objects := []client.Object{
		&juneauv1alpha1.AddressPool{},
		&juneauv1alpha1.BGPAdvertisement{},
		&juneauv1alpha1.BGPPeer{},
	}

	for _, obj := range objects {
		inf, err := c.GetInformer(ctx, obj)
		if err != nil {
			return fmt.Errorf("get informer for %T: %w", obj, err)
		}

		if _, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc: func(any) { i.Notify() },
			UpdateFunc: func(any, any) {
				i.Notify()
			},
			DeleteFunc: func(any) { i.Notify() },
		}); err != nil {
			return fmt.Errorf("add event handler for %T: %w", obj, err)
		}
	}

	return nil
}
