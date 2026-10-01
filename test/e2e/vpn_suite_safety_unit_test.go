package e2e

import (
	"reflect"
	"testing"
)

func TestControllerMakePinsSuiteCluster(t *testing.T) {
	want := "KUBECTL=kubectl --context=kind-juneau-e2e"
	if got := controllerKubectlTarget(); got != want {
		t.Fatalf("controller make target = %q; want %q", got, want)
	}
}

func TestKubectlCommandArgsPinsSuiteCluster(t *testing.T) {
	original := []string{"delete", "namespace", "e2e-vpn"}
	want := []string{"--context=kind-juneau-e2e", "delete", "namespace", "e2e-vpn"}
	got := kubectlCommandArgs(original)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kubectl arguments = %v; want %v", got, want)
	}
	if !reflect.DeepEqual(original, []string{"delete", "namespace", "e2e-vpn"}) {
		t.Fatalf("input was changed: %v", original)
	}
}
