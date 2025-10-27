/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cert

import (
	"context"
	"fmt"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	webhookPort = 9443
)

// WebhookConfig holds configuration for webhook registration
type WebhookConfig struct {
	Namespace string
	NodeIP    string
	CABundle  []byte
}

// ApplyWebhookConfigurations creates or updates the webhook configurations
func ApplyWebhookConfigurations(ctx context.Context, k8sClient client.Client, config WebhookConfig) error {
	if err := applyMutatingWebhookConfiguration(ctx, k8sClient, config); err != nil {
		return fmt.Errorf("failed to apply mutating webhook configuration: %w", err)
	}

	if err := applyValidatingWebhookConfiguration(ctx, k8sClient, config); err != nil {
		return fmt.Errorf("failed to apply validating webhook configuration: %w", err)
	}

	return nil
}

func applyMutatingWebhookConfiguration(ctx context.Context, k8sClient client.Client, config WebhookConfig) error {
	failurePolicy := admissionv1.Fail
	sideEffects := admissionv1.SideEffectClassNone

	webhookConfig := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "juneau-mutating-webhook-configuration",
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name: "maddress-v1alpha1.kb.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					URL:      stringPtr(fmt.Sprintf("https://%s:%d/mutate-juneau-loutres-me-v1alpha1-address", config.NodeIP, webhookPort)),
					CABundle: config.CABundle,
				},
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{
							admissionv1.Create,
							admissionv1.Update,
						},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"juneau.loutres.me"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"addresses"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
			{
				Name: "msubnet-v1alpha1.kb.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					URL:      stringPtr(fmt.Sprintf("https://%s:%d/mutate-juneau-loutres-me-v1alpha1-subnet", config.NodeIP, webhookPort)),
					CABundle: config.CABundle,
				},
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{
							admissionv1.Create,
							admissionv1.Update,
						},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"juneau.loutres.me"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"subnets"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
			{
				Name: "mvpc-v1alpha1.kb.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					URL:      stringPtr(fmt.Sprintf("https://%s:%d/mutate-juneau-loutres-me-v1alpha1-vpc", config.NodeIP, webhookPort)),
					CABundle: config.CABundle,
				},
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{
							admissionv1.Create,
							admissionv1.Update,
						},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"juneau.loutres.me"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"vpcs"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	// Try to get existing configuration
	existing := &admissionv1.MutatingWebhookConfiguration{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: webhookConfig.Name}, existing)
	if err != nil {
		// Create new if doesn't exist
		if err := k8sClient.Create(ctx, webhookConfig); err != nil {
			return fmt.Errorf("failed to create mutating webhook configuration: %w", err)
		}
		return nil
	}

	// Update existing
	existing.Webhooks = webhookConfig.Webhooks
	if err := k8sClient.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update mutating webhook configuration: %w", err)
	}

	return nil
}

func applyValidatingWebhookConfiguration(ctx context.Context, k8sClient client.Client, config WebhookConfig) error {
	failurePolicy := admissionv1.Fail
	sideEffects := admissionv1.SideEffectClassNone

	webhookConfig := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "juneau-validating-webhook-configuration",
		},
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				Name: "vaddress-v1alpha1.kb.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					URL:      stringPtr(fmt.Sprintf("https://%s:%d/validate-juneau-loutres-me-v1alpha1-address", config.NodeIP, webhookPort)),
					CABundle: config.CABundle,
				},
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{
							admissionv1.Create,
							admissionv1.Update,
						},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"juneau.loutres.me"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"addresses"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
			{
				Name: "vsubnet-v1alpha1.kb.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					URL:      stringPtr(fmt.Sprintf("https://%s:%d/validate-juneau-loutres-me-v1alpha1-subnet", config.NodeIP, webhookPort)),
					CABundle: config.CABundle,
				},
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{
							admissionv1.Create,
							admissionv1.Update,
						},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"juneau.loutres.me"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"subnets"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
			{
				Name: "vvpc-v1alpha1.kb.io",
				ClientConfig: admissionv1.WebhookClientConfig{
					URL:      stringPtr(fmt.Sprintf("https://%s:%d/validate-juneau-loutres-me-v1alpha1-vpc", config.NodeIP, webhookPort)),
					CABundle: config.CABundle,
				},
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{
							admissionv1.Create,
							admissionv1.Update,
						},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"juneau.loutres.me"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"vpcs"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	// Try to get existing configuration
	existing := &admissionv1.ValidatingWebhookConfiguration{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: webhookConfig.Name}, existing)
	if err != nil {
		// Create new if doesn't exist
		if err := k8sClient.Create(ctx, webhookConfig); err != nil {
			return fmt.Errorf("failed to create validating webhook configuration: %w", err)
		}
		return nil
	}

	// Update existing
	existing.Webhooks = webhookConfig.Webhooks
	if err := k8sClient.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update validating webhook configuration: %w", err)
	}

	return nil
}

// stringPtr returns a pointer to the string value
func stringPtr(s string) *string {
	return &s
}
