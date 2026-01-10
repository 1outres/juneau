package kube

import (
	"context"
	"fmt"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Runtime struct {
	cache  cache.Cache
	client client.Client
}

func NewRuntime(cfg *rest.Config, scheme *runtime.Scheme) (*Runtime, error) {
	c, err := cache.New(cfg, cache.Options{
		Scheme: scheme,
		ByObject: map[client.Object]cache.ByObject{
			&juneauv1alpha1.AddressPool{}:      {},
			&juneauv1alpha1.BGPAdvertisement{}: {},
			&juneauv1alpha1.BGPPeer{}:          {},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}

	cl, err := client.New(cfg, client.Options{
		Scheme: scheme,
		Cache: &client.CacheOptions{
			Reader: c,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	return &Runtime{
		cache:  c,
		client: cl,
	}, nil
}

func (r *Runtime) Cache() cache.Cache {
	return r.cache
}

func (r *Runtime) Client() client.Client {
	return r.client
}

func (r *Runtime) Start(ctx context.Context) error {
	return r.cache.Start(ctx)
}

func (r *Runtime) WaitForSync(ctx context.Context) error {
	if ok := r.cache.WaitForCacheSync(ctx); !ok {
		return fmt.Errorf("cache sync failed")
	}
	return nil
}
