package controller

import (
	"os"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestVPNManagerRBAC(t *testing.T) {
	contents, err := os.ReadFile("../../config/rbac/role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal(contents, &role); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		group, resource, verb string
	}{
		{"", "pods", "create"},
		{"", "pods", "delete"},
		{"", "secrets", "list"},
		{"", "secrets", "watch"},
		{"juneau.loutres.me", "vpns", "get"},
		{"juneau.loutres.me", "vpns", "list"},
		{"juneau.loutres.me", "vpns", "watch"},
		{"juneau.loutres.me", "vpns", "update"},
		{"juneau.loutres.me", "vpns/status", "update"},
		{"juneau.loutres.me", "vpns/finalizers", "update"},
	} {
		found := false
		for _, rule := range role.Rules {
			if containsRuleItem(rule.APIGroups, check.group) && containsRuleItem(rule.Resources, check.resource) && containsRuleItem(rule.Verbs, check.verb) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("manager role lacks %s %s/%s", check.verb, check.group, check.resource)
		}
	}
}

func containsRuleItem(items []string, item string) bool {
	for _, value := range items {
		if value == item || value == "*" {
			return true
		}
	}
	return false
}
