package kubeclient

import (
	"context"
	"fmt"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/pkg/client/clientset/versioned"
	juneauexternalversions "github.com/1outres/juneau/controller/pkg/client/informers/externalversions"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Client interface for Juneau custom resources
type Client interface {
	Juneauv1alpha1() Juneauv1alpha1Interface
	Corev1() Corev1Interface
	Start(ctx context.Context) error
	WaitForCacheSync(ctx context.Context) error

	JuneauSharedInformerFactory() juneauexternalversions.SharedInformerFactory
}

// Juneauv1alpha1Interface provides access to v1alpha1 resources
type Juneauv1alpha1Interface interface {
	Vpc() *CachedClient[juneauv1alpha1.Vpc]
	Subnet() *CachedClient[juneauv1alpha1.Subnet]
	SubnetLease() *CachedClient[juneauv1alpha1.SubnetLease]
	Address(namespace string) *CachedClient[juneauv1alpha1.Address]
}

type Corev1Interface interface {
	Pod(namespace string) *CachedClient[corev1.Pod]
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
	clientset kubernetes.Interface
	factory   informers.SharedInformerFactory

	juneauclientset versioned.Interface
	juneaufactory   juneauexternalversions.SharedInformerFactory
}

// NewClient creates a new Juneau client with informer-based caching
func NewClient(config *rest.Config) (Client, error) {
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	factory := informers.NewSharedInformerFactory(cs, 30*time.Second)

	juneaucs, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	// Create informer juneaufactory with 30 second resync period
	juneaufactory := juneauexternalversions.NewSharedInformerFactory(juneaucs, 30*time.Second)

	return &client{
		clientset: cs,
		factory: factory,
		juneauclientset: juneaucs,
		juneaufactory:   juneaufactory,
	}, nil
}

// Juneauv1alpha1 returns the v1alpha1 interface
func (c *client) Juneauv1alpha1() Juneauv1alpha1Interface {
	return &juneauv1alpha1Client{client: c}
}

func (c *client) Corev1() Corev1Interface {
	return &corev1Client{client: c}
}

// Start starts all informers
func (c *client) Start(ctx context.Context) error {
	c.factory.Start(ctx.Done())
	c.juneaufactory.Start(ctx.Done())
	return nil
}

// WaitForCacheSync waits for all informer caches to sync
func (c *client) WaitForCacheSync(ctx context.Context) error {
	synced := c.juneaufactory.WaitForCacheSync(ctx.Done())
	for resourceType, ok := range synced {
		if !ok {
			return fmt.Errorf("failed to sync cache for %v", resourceType)
		}
	}
	return nil
}

func (c *client) JuneauSharedInformerFactory() juneauexternalversions.SharedInformerFactory {
	return c.juneaufactory
}

// juneauv1alpha1Client implements V1alpha1Interface
type juneauv1alpha1Client struct {
	client *client
}

func (v *juneauv1alpha1Client) Vpc() *CachedClient[juneauv1alpha1.Vpc] {
	return &CachedClient[juneauv1alpha1.Vpc]{
		clientset: v.client.juneauclientset.ApiV1alpha1().Vpcs(),
		lister:    v.client.juneaufactory.Api().V1alpha1().Vpcs().Lister(),
	}
}

func (v *juneauv1alpha1Client) Subnet() *CachedClient[juneauv1alpha1.Subnet] {
	return &CachedClient[juneauv1alpha1.Subnet]{
		clientset: v.client.juneauclientset.ApiV1alpha1().Subnets(),
		lister:    v.client.juneaufactory.Api().V1alpha1().Subnets().Lister(),
	}
}

func (v *juneauv1alpha1Client) SubnetLease() *CachedClient[juneauv1alpha1.SubnetLease] {
	return &CachedClient[juneauv1alpha1.SubnetLease]{
		clientset: v.client.juneauclientset.ApiV1alpha1().SubnetLeases(),
		lister:    v.client.juneaufactory.Api().V1alpha1().SubnetLeases().Lister(),
	}
}

func (v *juneauv1alpha1Client) Address(namespace string) *CachedClient[juneauv1alpha1.Address] {
	return &CachedClient[juneauv1alpha1.Address]{
		clientset: v.client.juneauclientset.ApiV1alpha1().Addresses(namespace),
		lister:    v.client.juneaufactory.Api().V1alpha1().Addresses().Lister().Addresses(namespace),
	}
}

type corev1Client struct {
	client *client
}

func (v *corev1Client) Pod(namespace string) *CachedClient[corev1.Pod] {
	return &CachedClient[corev1.Pod]{
		clientset: v.client.clientset.CoreV1().Pods(namespace),
		lister:    v.client.factory.Core().V1().Pods().Lister().Pods(namespace),
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

