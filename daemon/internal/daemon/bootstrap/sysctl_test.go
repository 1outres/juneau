package bootstrap

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPodVethSysctlGlobMatchesEveryPodNIC(t *testing.T) {
	matching := []string{
		"eth0+0123456789",
		"eth1+0123456789",
		"data0+0123456789",
	}
	for _, name := range matching {
		ok, err := filepath.Match(podVethSysctlGlob, name)
		if err != nil {
			t.Fatalf("Match(%q, %q): %v", podVethSysctlGlob, name, err)
		}
		if !ok {
			t.Errorf("%q must be covered by the drop-in", name)
		}
	}
}

func TestPodVethSysctlGlobSpareTheHostNICs(t *testing.T) {
	skipped := []string{
		"eth0",
		"ens3",
		"lo",
		JuneauNodeIfaceName,
		JuneauNodeHostIfaceName,
	}
	for _, name := range skipped {
		ok, err := filepath.Match(podVethSysctlGlob, name)
		if err != nil {
			t.Fatalf("Match(%q, %q): %v", podVethSysctlGlob, name, err)
		}
		if ok {
			t.Errorf("%q is not a pod veth and must keep its own settings", name)
		}
	}
}

func TestSysctlDropInCoversBothPodVethSettings(t *testing.T) {
	for _, setting := range []string{"rp_filter = 0", "accept_local = 1"} {
		want := "net.ipv4.conf." + podVethSysctlGlob + "." + setting
		if !strings.Contains(juneauSysctlDropInBody, want) {
			t.Errorf("drop-in must contain %q, got:\n%s", want, juneauSysctlDropInBody)
		}
	}
}
