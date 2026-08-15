package webhookapply

import (
	"testing"

	admv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/utils/ptr"
)

func TestPrepareMutatingEnablesProbeWebhookForCustomSubnetPods(t *testing.T) {
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
	if got := probe.MatchConditions[0].Expression; got != probeSubnetMatch {
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
