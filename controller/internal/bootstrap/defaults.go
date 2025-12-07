package bootstrap

import (
	"context"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	defaultVpcName    = "default"
	defaultSubnetName = "default"
)

// EnsureDefaults creates default VPC and Subnet if they don't already exist.
func EnsureDefaults(ctx context.Context, c client.Client, logger logr.Logger, defaultSubnetCIDR string) error {
	if err := ensureDefaultVpc(ctx, c, logger); err != nil {
		return err
	}

	if err := ensureDefaultSubnet(ctx, c, logger, defaultSubnetCIDR); err != nil {
		return err
	}

	return nil
}

func ensureDefaultVpc(ctx context.Context, c client.Client, logger logr.Logger) error {
	var vpc juneauv1alpha1.Vpc
	if err := c.Get(ctx, client.ObjectKey{Name: defaultVpcName}, &vpc); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		logger.Info("creating default VPC")
		return c.Create(ctx, &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultVpcName,
			},
			Spec: juneauv1alpha1.VpcSpec{},
		})
	}

	return nil
}

func ensureDefaultSubnet(ctx context.Context, c client.Client, logger logr.Logger, cidr string) error {
	var subnet juneauv1alpha1.Subnet
	if err := c.Get(ctx, client.ObjectKey{Name: defaultSubnetName}, &subnet); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		logger.Info("creating default Subnet", "cidr", cidr)
		return c.Create(ctx, &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultSubnetName,
			},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  defaultVpcName,
				CIDR: cidr,
			},
		})
	}

	return nil
}
