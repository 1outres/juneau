package kubeclient

import (
	"context"
	"fmt"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/pkg/client/clientset/versioned"
	"github.com/1outres/juneau/controller/pkg/client/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Client interface for Juneau custom resources
type Client interface {
	V1alpha1() V1alpha1Interface
	Start(ctx context.Context) error
	WaitForCacheSync(ctx context.Context) error
}

// V1alpha1Interface provides access to v1alpha1 resources
type V1alpha1Interface interface {
	Vpc() *CachedClient[juneauv1alpha1.Vpc]
	Subnet() *CachedClient[juneauv1alpha1.Subnet]
	SubnetLease() *CachedClient[juneauv1alpha1.SubnetLease]
}

// ResourceInterface provides CRUD operations for a resource
type ResourceInterface[T any] interface {
	Create(ctx context.Context, obj *T, opts metav1.CreateOptions) (*T, error)
	Update(ctx context.Context, obj *T, opts metav1.UpdateOptions) (*T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*T, error)
}

type ResourceLister[T any] interface {
	List(selector labels.Selector) (ret []*T, err error)
	Get(name string) (*T, error)
}

// client implements Client interface
type client struct {
	clientset versioned.Interface
	factory   externalversions.SharedInformerFactory
}

// NewClient creates a new Juneau client with informer-based caching
func NewClient(config *rest.Config) (Client, error) {
	cs, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	// Create informer factory with 30 second resync period
	factory := externalversions.NewSharedInformerFactory(cs, 30*time.Second)

	return &client{
		clientset: cs,
		factory:   factory,
	}, nil
}

// V1alpha1 returns the v1alpha1 interface
func (c *client) V1alpha1() V1alpha1Interface {
	return &v1alpha1Client{client: c}
}

// Start starts all informers
func (c *client) Start(ctx context.Context) error {
	c.factory.Start(ctx.Done())
	return nil
}

// WaitForCacheSync waits for all informer caches to sync
func (c *client) WaitForCacheSync(ctx context.Context) error {
	synced := c.factory.WaitForCacheSync(ctx.Done())
	for resourceType, ok := range synced {
		if !ok {
			return fmt.Errorf("failed to sync cache for %v", resourceType)
		}
	}
	return nil
}

// v1alpha1Client implements V1alpha1Interface
type v1alpha1Client struct {
	client *client
}

func (v *v1alpha1Client) Vpc() *CachedClient[juneauv1alpha1.Vpc] {
	return &CachedClient[juneauv1alpha1.Vpc]{
		clientset: v.client.clientset.ApiV1alpha1().Vpcs(),
		lister:    v.client.factory.Api().V1alpha1().Vpcs().Lister(),
	}
}

func (v *v1alpha1Client) Subnet() *CachedClient[juneauv1alpha1.Subnet] {
	return &CachedClient[juneauv1alpha1.Subnet]{
		clientset: v.client.clientset.ApiV1alpha1().Subnets(),
		lister:    v.client.factory.Api().V1alpha1().Subnets().Lister(),
	}
}

func (v *v1alpha1Client) SubnetLease() *CachedClient[juneauv1alpha1.SubnetLease] {
	return &CachedClient[juneauv1alpha1.SubnetLease]{
		clientset: v.client.clientset.ApiV1alpha1().SubnetLeases(),
		lister:    v.client.factory.Api().V1alpha1().SubnetLeases().Lister(),
	}
}

type CachedClient[T any] struct {
	clientset ResourceInterface[T]
	lister    ResourceLister[T]
}

func (c *CachedClient[T]) Get(ctx context.Context, name string, opts metav1.GetOptions) (*T, error) {
	return c.lister.Get(name)
}

func (c *CachedClient[T]) List(ctx context.Context, opts metav1.ListOptions) ([]*T, error) {
	// Use lister (cache) for List operations
	selector := labels.Everything()
	if opts.LabelSelector != "" {
		var err error
		selector, err = labels.Parse(opts.LabelSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to parse label selector: %w", err)
		}
	}

	vpcs, err := c.lister.List(selector)
	if err != nil {
		return nil, err
	}

	return vpcs, nil
}

func (c *CachedClient[T]) Create(ctx context.Context, obj *T, opts metav1.CreateOptions) (*T, error) {
	return c.clientset.Create(ctx, obj, opts)
}

func (c *CachedClient[T]) Update(ctx context.Context, obj *T, opts metav1.UpdateOptions) (*T, error) {
	return c.clientset.Update(ctx, obj, opts)
}

func (c *CachedClient[T]) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.clientset.Delete(ctx, name, opts)
}

func (c *CachedClient[T]) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*T, error) {
	return c.clientset.Patch(ctx, name, pt, data, opts, subresources...)
}

