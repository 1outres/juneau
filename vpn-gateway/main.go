package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

func command(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeConfig(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func networkSteps(c Config) ([][]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	steps := [][]string{
		{"iptables", "-w", "-P", "FORWARD", "DROP"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.default.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.ext0.rp_filter=0"},
		{"ip", "link", "add", "ipsec0", "type", "xfrm", "if_id", "42", "dev", "ext0"},
		{"sysctl", "-w", "net.ipv4.conf.ipsec0.rp_filter=0"},
		{"ip", "address", "add", c.LocalTunnelIP + "/32", "dev", "ipsec0"},
		{"ip", "link", "set", "ipsec0", "up"},
		{"ip", "route", "replace", c.RemoteTunnelIP + "/32", "dev", "ipsec0", "src", c.LocalTunnelIP},
		{"ip", "rule", "add", "priority", "100", "iif", "eth0", "lookup", "200"},
		{"ip", "route", "replace", "prohibit", "default", "table", "200"},
		{"iptables", "-w", "-A", "FORWARD", "-i", "ipsec0", "-o", "eth0", "-m", "addrtype", "--src-type", "LOCAL", "-j", "DROP"},
	}
	for _, route := range c.RemoteRoutes {
		steps = append(steps, []string{"ip", "route", "replace", route, "dev", "ipsec0", "table", "200"})
		for _, advertised := range c.AdvertisedRoutes {
			steps = append(steps, []string{"iptables", "-w", "-A", "FORWARD", "-i", "ipsec0", "-o", "eth0", "-s", route, "-d", advertised, "-j", "ACCEPT"})
		}
		steps = append(steps, []string{"iptables", "-w", "-A", "FORWARD", "-i", "eth0", "-o", "ipsec0", "-d", route, "-j", "ACCEPT"})
	}
	return steps, nil
}

func configureNetwork(ctx context.Context, c Config) error {
	steps, err := networkSteps(c)
	if err != nil {
		return err
	}
	for _, step := range steps {
		if err := command(ctx, step[0], step[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func start(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	return cmd, nil
}

func run(ctx context.Context) error {
	cfg, err := loadEnv()
	if err != nil {
		return err
	}
	swan, err := renderSwanctl(cfg)
	if err != nil {
		return err
	}
	bird, err := renderBird(cfg)
	if err != nil {
		return err
	}
	if err = writeConfig("/etc/swanctl/swanctl.conf", swan); err != nil {
		return err
	}
	if err = writeConfig("/run/juneau-vpn/bird.conf", bird); err != nil {
		return err
	}
	if err = configureNetwork(ctx, cfg); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	charon, err := start(ctx, "/usr/lib/ipsec/charon")
	if err != nil {
		return err
	}
	exits := make(chan error, 2)
	go func() { exits <- fmt.Errorf("charon exited: %v", charon.Wait()) }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if err = exec.CommandContext(ctx, "swanctl", "--load-all").Run(); err == nil {
			break
		}
		select {
		case exit := <-exits:
			return exit
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("loading IPsec configuration: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	birdCmd, err := start(ctx, "bird", "-f", "-c", "/run/juneau-vpn/bird.conf", "-s", "/run/juneau-vpn/bird.ctl")
	if err != nil {
		return err
	}
	go func() { exits <- fmt.Errorf("bird exited: %v", birdCmd.Wait()) }()
	select {
	case err = <-exits:
		return err
	case <-ctx.Done():
		return nil
	}
}

var establishedBGP = regexp.MustCompile(`(?m)^\s*BGP state:\s+Established\s*$`)

func healthy(sa, bgp string) bool {
	ike, child := false, false
	for _, line := range strings.Split(sa, "\n") {
		if strings.HasPrefix(line, "juneau: #") && strings.Contains(line, ", ESTABLISHED,") {
			ike = true
		}
		if strings.HasPrefix(line, "  juneau: #") && strings.Contains(line, ", INSTALLED,") {
			child = true
		}
	}
	return ike && child && establishedBGP.MatchString(bgp)
}

func health(ctx context.Context) error {
	sa, err := exec.CommandContext(ctx, "swanctl", "--list-sas").Output()
	if err != nil {
		return fmt.Errorf("query IPsec SAs: %w", err)
	}
	bgp, err := exec.CommandContext(ctx, "birdc", "-s", "/run/juneau-vpn/bird.ctl", "show", "protocols", "all", birdProtocol).Output()
	if err != nil {
		return fmt.Errorf("query BGP peer: %w", err)
	}
	if !healthy(string(sa), string(bgp)) {
		return errors.New("IPsec child SA or BGP session not established")
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var err error
	switch {
	case len(os.Args) == 1:
		err = run(ctx)
	case len(os.Args) == 2 && os.Args[1] == "health":
		check, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err = health(check)
	default:
		err = errors.New("usage: vpn-gateway [health]")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
