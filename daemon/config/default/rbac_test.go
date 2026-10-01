package defaultconfig_test

import (
	"os"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestDaemonCanReadCrossVPCRoutes(t *testing.T) {
	data, err := os.ReadFile("rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}

	bindings := map[string]bool{}
	for _, document := range strings.Split(string(data), "\n---") {
		var binding rbacv1.ClusterRoleBinding
		if err := yaml.Unmarshal([]byte(document), &binding); err != nil {
			t.Fatal(err)
		}
		if binding.Kind != "ClusterRoleBinding" {
			continue
		}
		for _, subject := range binding.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Name == "cni-daemon" && subject.Namespace == "kube-system" {
				bindings[binding.RoleRef.Name] = true
			}
		}
	}

	for _, role := range []string{
		"juneau-vpcpeering-viewer-role",
		"juneau-transitgatewayattachment-viewer-role",
	} {
		if !bindings[role] {
			t.Errorf("cni-daemon has no binding for %s", role)
		}
	}
}
