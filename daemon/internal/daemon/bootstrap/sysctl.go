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

	// host-network Service backend が同居するノードでは pod_egress が
	// (src=PodIP, dst=NodeIP) のまま TC_ACT_OK で local input に渡す。
	// この packet は juneau_node 上に着信するが reverse path は
	// juneau_node_h なので rp_filter=1 (strict) では drop される。
	// rp_filter=2 (loose) に下げ、accept_local=1 で同経路を許可する。
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+JuneauNodeIfaceName+"/rp_filter", "2"); err != nil {
		return fmt.Errorf("failed to set rp_filter on %s: %w", JuneauNodeIfaceName, err)
	}
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+JuneauNodeIfaceName+"/accept_local", "1"); err != nil {
		return fmt.Errorf("failed to set accept_local on %s: %w", JuneauNodeIfaceName, err)
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
