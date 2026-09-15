package webhookapply

import (
	"testing"

	"github.com/google/cel-go/cel"
	admv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/utils/ptr"
)

func TestPrepareMutatingEnablesProbeWebhookForCustomNetworkPods(t *testing.T) {
	configuration := &admv1.MutatingWebhookConfiguration{
		Webhooks: []admv1.MutatingWebhook{{
			Name: "ordinary.example.com",
			ClientConfig: admv1.WebhookClientConfig{
				Service: &admv1.ServiceReference{Path: ptr.To("/ordinary")},
			},
		}, {
			Name: probeWebhookName,
			ClientConfig: admv1.WebhookClientConfig{
				Service: &admv1.ServiceReference{Path: ptr.To("/mutate--v1-pod-probes")},
			},
		}},
	}
	prepareMutating(configuration, "10.0.0.2", []byte("ca"), "juneau-", true)

	if len(configuration.Webhooks) != 2 {
		t.Fatalf("expected two webhooks, got %d", len(configuration.Webhooks))
	}
	probe := configuration.Webhooks[1]
	if len(probe.MatchConditions) != 1 {
		t.Fatalf("expected one match condition, got %d", len(probe.MatchConditions))
	}
	if got := probe.MatchConditions[0].Expression; got != probeRewriteMatch {
		t.Fatalf("unexpected match expression: %s", got)
	}
	if got := ptr.Deref(probe.ClientConfig.URL, ""); got != "https://10.0.0.2:9443/mutate--v1-pod-probes" {
		t.Fatalf("unexpected webhook URL: %s", got)
	}
}

func TestPrepareMutatingRemovesProbeWebhookWhenDisabled(t *testing.T) {
	configuration := &admv1.MutatingWebhookConfiguration{
		Webhooks: []admv1.MutatingWebhook{{
			Name: "ordinary.example.com",
		}, {
			Name: probeWebhookName,
		}},
	}

	prepareMutating(configuration, "10.0.0.2", []byte("ca"), "juneau-", false)

	if len(configuration.Webhooks) != 1 {
		t.Fatalf("expected only the ordinary webhook, got %d", len(configuration.Webhooks))
	}
	if configuration.Webhooks[0].Name != "ordinary.example.com" {
		t.Fatalf("unexpected remaining webhook: %s", configuration.Webhooks[0].Name)
	}
}

// TestProbeRewriteMatch evaluates the match condition the way the API
// server does: object is the Pod as an untyped map. The condition only has
// to let through every Pod the probe defaulter may rewrite; the defaulter
// makes the final decision.
func TestProbeRewriteMatch(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("object", cel.DynType))
	if err != nil {
		t.Fatalf("create the CEL environment: %v", err)
	}
	ast, issues := env.Compile(probeRewriteMatch)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile the match condition: %v", issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("build the CEL program: %v", err)
	}

	cases := []struct {
		name        string
		annotations map[string]any
		want        bool
	}{
		{name: "a Pod without annotations", want: false},
		{name: "a Pod on the default Subnet", annotations: map[string]any{"juneau.loutres.me/subnet": "default"}, want: false},
		{name: "a Pod with an empty subnet annotation", annotations: map[string]any{"juneau.loutres.me/subnet": ""}, want: false},
		{name: "a Pod on a custom Subnet", annotations: map[string]any{"juneau.loutres.me/subnet": "web"}, want: true},
		{
			name:        "a Pod whose eth0 comes from a networks entry",
			annotations: map[string]any{"juneau.loutres.me/networks": `[{"interface":"eth0","subnet":"web"}]`},
			want:        true,
		},
		{name: "a Pod whose eth0 carries an ElasticIP", annotations: map[string]any{"juneau.loutres.me/elastic-ip": "web"}, want: false},
		{name: "a Pod with unrelated annotations", annotations: map[string]any{"example.com/owner": "team-a"}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]any{"name": "web-0"}
			if tc.annotations != nil {
				metadata["annotations"] = tc.annotations
			}
			out, _, err := program.Eval(map[string]any{"object": map[string]any{"metadata": metadata}})
			if err != nil {
				t.Fatalf("evaluate the match condition: %v", err)
			}
			if got := out.Value(); got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
}
