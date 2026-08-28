package bootstrap

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

const juneauSysctlDropInDir = "/run/sysctl.d"

// juneauSysctlDropInPath: "60-" sorts after /lib/sysctl.d/50-default.conf
// so systemd-sysctl's last-write-wins pass keeps our rp_filter=0.
const juneauSysctlDropInPath = juneauSysctlDropInDir + "/60-juneau.conf"

// podVethSysctlGlob matches the host side of every pod NIC, named
// "<ifname>+<container id>". A pod can carry more than one NIC, so the
// pattern keys off the '+' the CNI server puts in the name rather than
// off a fixed interface name. Host NICs never carry a '+', which is what
// keeps their own settings out of reach.
const podVethSysctlGlob = "*+*"

// juneauSysctlDropInBody undoes 50-default.conf's
// net.ipv4.conf.*.rp_filter=2 for juneau CNI veths. Without it the
// systemd-sysctl run udev triggers on every net-device add races with
// PodAttacher's per-iface write, dropping handle_service_host_local
// packets as martian source.
var juneauSysctlDropInBody = fmt.Sprintf(`# Managed by juneau-cni-daemon.
net.ipv4.conf.%[1]s.rp_filter = 0
net.ipv4.conf.%[1]s.accept_local = 1
`, podVethSysctlGlob)

func ConfigureSysctl() error {
	if err := InstallSysctlDropIn(); err != nil {
		return err
	}

	// HOST_LOCAL Service forwarding hands a packet to the kernel with
	// src=PodIP on the Pod's host-side veth, but the reverse route to
	// PodIP is via juneau_node_h — an asymmetric path that any
	// reverse-path check (strict or loose) would drop. The kernel
	// honours max(all/rp_filter, iface/rp_filter), so disabling on
	// `all` is mandatory; per-Pod veths additionally get the loose
	// setting via PodAttacher at attach time.
	if err := ConfigureLooseRPFilter("all"); err != nil {
		return err
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

// ConfigureJuneauNodeSysctl writes the per-iface settings of the
// juneau_node veth pair. It sits with the converger that owns the pair
// rather than in ConfigureSysctl, because a pair rebuilt while the
// daemon runs comes back with the kernel defaults.
//
// juneau_node needs accept_local=1 for the reply leg of a Service flow,
// where src=NodeIP arrives on a local address. send_redirects is off on
// juneau_node_h so the host does not answer overlay traffic with ICMP
// redirects.
func ConfigureJuneauNodeSysctl() error {
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+JuneauNodeHostIfaceName+"/send_redirects", "0"); err != nil {
		return fmt.Errorf("set send_redirects on %s: %w", JuneauNodeHostIfaceName, err)
	}
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+JuneauNodeIfaceName+"/accept_local", "1"); err != nil {
		return fmt.Errorf("set accept_local on %s: %w", JuneauNodeIfaceName, err)
	}
	return nil
}

// InstallSysctlDropIn writes juneauSysctlDropInPath. Idempotent.
func InstallSysctlDropIn() error {
	if err := os.MkdirAll(juneauSysctlDropInDir, 0755); err != nil {
		return fmt.Errorf("ensure %s: %w", juneauSysctlDropInDir, err)
	}
	if err := os.WriteFile(juneauSysctlDropInPath, []byte(juneauSysctlDropInBody), 0644); err != nil {
		return fmt.Errorf("write %s: %w", juneauSysctlDropInPath, err)
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

// DisableIPv6 turns IPv6 off on one interface.
//
// The gateway port of an L2Network is a veth in the host namespace with
// no address of its own. With IPv6 left on, the kernel would send
// router solicitations and multicast listener reports out of it, onto a
// segment that belongs to a tenant and carries whatever that tenant
// runs on it.
func DisableIPv6(iface string) error {
	path := "/proc/sys/net/ipv6/conf/" + iface + "/disable_ipv6"
	if err := writeSysctl(path, "1"); err != nil {
		if os.IsNotExist(err) {
			// A kernel built without IPv6 has nothing to turn off.
			return nil
		}
		return fmt.Errorf("turn IPv6 off on %s: %w", iface, err)
	}
	return nil
}
