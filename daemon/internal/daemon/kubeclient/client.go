package kubeclient

import (
	"context"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Client interface {
	V1alpha1() V1alpha1Interface
}

type V1alpha1Interface interface {
	Vpc() ResourceInterface[juneauv1alpha1.Vpc, juneauv1alpha1.VpcList]
	Subnet() ResourceInterface[juneauv1alpha1.Subnet, juneauv1alpha1.SubnetList]
	SubnetLease() ResourceInterface[juneauv1alpha1.SubnetLease, juneauv1alpha1.SubnetLeaseList]
}

type ResourceInterface[T any, L any] interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*T, error)
	List(ctx context.Context, opts metav1.ListOptions) (*L, error)
	Create(ctx context.Context, obj *T, opts metav1.CreateOptions) (*T, error)
	Update(ctx context.Context, obj *T, opts metav1.UpdateOptions) (*T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*T, error)
}
