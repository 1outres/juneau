package bootstrap

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

func ConfigureSysctl() error {
	// Match the rename of cni_host → juneau_node_h (Phase 4b-4).
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+JuneauNodeHostIfaceName+"/send_redirects", "0"); err != nil {
		return fmt.Errorf("failed to set send_redirects on %s: %w", JuneauNodeHostIfaceName, err)
	}

	// HOST_LOCAL Service forwarding hands a packet to the kernel with
	// src=PodIP on the Pod's host-side veth, but the reverse route to
	// PodIP is via juneau_node_h — an asymmetric path that any
	// reverse-path check (strict or loose) would drop. The kernel
	// honours max(all/rp_filter, iface/rp_filter), so disabling on
	// `all` is mandatory; per-Pod veths additionally get the loose
	// setting via PodAttacher at attach time. juneau_node only needs
	// accept_local=1 for the reply leg where src=NodeIP=local arrives.
	if err := ConfigureLooseRPFilter("all"); err != nil {
		return err
	}
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+JuneauNodeIfaceName+"/accept_local", "1"); err != nil {
		return fmt.Errorf("set accept_local on %s: %w", JuneauNodeIfaceName, err)
	}

	ipForward, err := readSysctl("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("failed to read ip_forward: %w", err)
	}

	if strings.TrimSpace(ipForward) != "1" {
		zap.S().Warn("IP forwarding is disabled.")
	}

	return nil
}

// ConfigureLooseRPFilter disables reverse-path filtering (rp_filter=0)
// and enables accept_local=1 on the given sysctl conf scope. Used for
// `all` and per-Pod veths to keep HOST_LOCAL Service forwarding alive
// despite its asymmetric routing — see ConfigureSysctl for context.
// The security trade-off matches what Cilium and other overlay CNIs
// adopt, and is acceptable because juneau validates source addresses
// in BPF before this point.
func ConfigureLooseRPFilter(scope string) error {
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+scope+"/rp_filter", "0"); err != nil {
		return fmt.Errorf("set rp_filter on %s: %w", scope, err)
	}
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+scope+"/accept_local", "1"); err != nil {
		return fmt.Errorf("set accept_local on %s: %w", scope, err)
	}
	return nil
}

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}

func readSysctl(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
