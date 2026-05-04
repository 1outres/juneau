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
	defaultVpcName                 = "default"
	defaultSubnetName              = "default"
	defaultSubnetVNIPoolName       = "subnet-vni"
	defaultRouteTablePoolName      = "route-table-id"
	defaultVpcIDPoolName           = "vpc-id"
	defaultNATGatewayIDPoolName    = "nat-gateway-id"
	defaultSecurityGroupIDPoolName = "security-group-id"
	defaultNetworkACLIDPoolName    = "network-acl-id"
)

// EnsureDefaults creates default VPC and Subnet if they don't already exist.
func EnsureDefaults(ctx context.Context, c client.Client, logger logr.Logger, defaultSubnetCIDR string) error {
	if err := ensureDefaultVpc(ctx, c, logger); err != nil {
		return err
	}

	if err := ensureDefaultSubnet(ctx, c, logger, defaultSubnetCIDR); err != nil {
		return err
	}

	if err := ensureDefaultAllocationPools(ctx, c, logger); err != nil {
		return err
	}

	return nil
}

func ensureDefaultAllocationPools(ctx context.Context, c client.Client, logger logr.Logger) error {
	pools := []juneauv1alpha1.AllocationPool{
		{
			ObjectMeta: metav1.ObjectMeta{Name: defaultSubnetVNIPoolName},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number: &juneauv1alpha1.AllocationPoolNumberSpec{
					Min: 2,
					Max: 0xFFFFFF,
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: defaultRouteTablePoolName},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number: &juneauv1alpha1.AllocationPoolNumberSpec{
					Min: 2,
					Max: uint64(^uint32(0)),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: defaultVpcIDPoolName},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number: &juneauv1alpha1.AllocationPoolNumberSpec{
					Min: 2,
					Max: uint64(^uint32(0)),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: defaultNATGatewayIDPoolName},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number: &juneauv1alpha1.AllocationPoolNumberSpec{
					Min: 1,
					Max: uint64(^uint32(0)),
				},
			},
		},
		{
			// security-group-id is a number-typed pool that hands out
			// stable cluster-wide GroupIDs to SecurityGroup resources.
			// The data plane (BPF) keys its rule tables by GroupID, so
			// these numbers must outlive transient Kubernetes object
			// names. Min=1 keeps 0 as the "no SG" sentinel.
			ObjectMeta: metav1.ObjectMeta{Name: defaultSecurityGroupIDPoolName},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number: &juneauv1alpha1.AllocationPoolNumberSpec{
					Min: 1,
					Max: 65535,
				},
			},
		},
		{
			// network-acl-id mirrors security-group-id: a stable
			// cluster-wide identifier the data plane keys
			// acl_meta_map / acl_rule_table by. The pool is sized
			// independently because ACL counts are typically smaller
			// than SG counts (one ACL per Subnet boundary versus many
			// SGs per Pod), but uses the same Min=1 sentinel rule so
			// 0 reliably means "no ACL programmed".
			ObjectMeta: metav1.ObjectMeta{Name: defaultNetworkACLIDPoolName},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number: &juneauv1alpha1.AllocationPoolNumberSpec{
					Min: 1,
					Max: 65535,
				},
			},
		},
	}

	for _, pool := range pools {
		var existing juneauv1alpha1.AllocationPool
		if err := c.Get(ctx, client.ObjectKey{Name: pool.Name}, &existing); err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
			logger.Info("creating default AllocationPool", "name", pool.Name)
			if err := c.Create(ctx, &pool); err != nil {
				return err
			}
		}
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
			Spec: juneauv1alpha1.VpcSpec{
				// Enable Service routing on the default VPC so
				// Services without the juneau.loutres.me/vpc
				// annotation (which implicitly target default)
				// are not rejected by the webhook. While default
				// Subnet Pods are still routed to cni_host and
				// use kube-proxy / iptables, this keeps the
				// CRD-level surface consistent.
				EnableService: true,
			},
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
