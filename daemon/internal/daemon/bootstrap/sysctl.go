package bootstrap

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

func ConfigureSysctl() error {
	if err := writeSysctl("/proc/sys/net/ipv4/conf/cni_host/send_redirects", "0"); err != nil {
		return fmt.Errorf("failed to set send_redirects: %w", err)
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
