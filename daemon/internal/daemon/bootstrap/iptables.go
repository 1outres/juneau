package bootstrap

import (
	"context"
	"fmt"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/coreos/go-iptables/iptables"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func EnsureMasqueradeRule(ctx context.Context, cl client.Client, masqueradeInterface string) error {
	var subnet juneauv1alpha1.Subnet
	if err := cl.Get(ctx, client.ObjectKey{Name: "default"}, &subnet); err != nil {
		return fmt.Errorf("failed to get default subnet: %w", err)
	}

	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to create iptables instance: %w", err)
	}

	exists, err := ipt.Exists(
		"nat",
		"POSTROUTING",
		"-s", subnet.Spec.CIDR,
		"-o", masqueradeInterface,
		"-j", "MASQUERADE",
	)
	if err != nil {
		return fmt.Errorf("failed to check rule existence: %w", err)
	}

	if exists {
		return nil
	}

	if err := ipt.Append(
		"nat",
		"POSTROUTING",
		"-s", subnet.Spec.CIDR,
		"-o", masqueradeInterface,
		"-j", "MASQUERADE",
	); err != nil {
		return fmt.Errorf("failed to append rule: %w", err)
	}

	return nil
}
