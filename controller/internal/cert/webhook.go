package cert

import (
	"context"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/internal/webhookmanifests"
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
// by loading them from the embedded manifests and injecting the node IP and CA bundle
func ApplyWebhookConfigurations(ctx context.Context, k8sClient client.Client, config WebhookConfig) error {
	// Parse the embedded YAML into webhook configurations
	mutatingConfig, validatingConfig, err := parseWebhookManifests()
	if err != nil {
		return fmt.Errorf("failed to parse webhook manifests: %w", err)
	}

	// Update clientConfig to use URL with node IP instead of service
	if err := updateMutatingWebhookConfig(mutatingConfig, config); err != nil {
		return fmt.Errorf("failed to update mutating webhook config: %w", err)
	}

	if err := updateValidatingWebhookConfig(validatingConfig, config); err != nil {
		return fmt.Errorf("failed to update validating webhook config: %w", err)
	}

	// Apply the configurations
	if err := applyMutatingWebhookConfiguration(ctx, k8sClient, mutatingConfig); err != nil {
		return fmt.Errorf("failed to apply mutating webhook configuration: %w", err)
	}

	if err := applyValidatingWebhookConfiguration(ctx, k8sClient, validatingConfig); err != nil {
		return fmt.Errorf("failed to apply validating webhook configuration: %w", err)
	}

	return nil
}

// parseWebhookManifests parses the embedded YAML into webhook configuration objects
func parseWebhookManifests() (*admissionv1.MutatingWebhookConfiguration, *admissionv1.ValidatingWebhookConfiguration, error) {
	var mutatingConfig *admissionv1.MutatingWebhookConfiguration
	var validatingConfig *admissionv1.ValidatingWebhookConfiguration

	// Split the YAML by document separator
	documents := strings.Split(webhookmanifests.Manifests, "---")

	for _, doc := range documents {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		// Try to decode as MutatingWebhookConfiguration
		var mwc admissionv1.MutatingWebhookConfiguration
		if err := yaml.Unmarshal([]byte(doc), &mwc); err == nil && mwc.Kind == "MutatingWebhookConfiguration" {
			mutatingConfig = &mwc
			continue
		}

		// Try to decode as ValidatingWebhookConfiguration
		var vwc admissionv1.ValidatingWebhookConfiguration
		if err := yaml.Unmarshal([]byte(doc), &vwc); err == nil && vwc.Kind == "ValidatingWebhookConfiguration" {
			validatingConfig = &vwc
			continue
		}
	}

	if mutatingConfig == nil {
		return nil, nil, fmt.Errorf("mutating webhook configuration not found in manifests")
	}

	if validatingConfig == nil {
		return nil, nil, fmt.Errorf("validating webhook configuration not found in manifests")
	}

	return mutatingConfig, validatingConfig, nil
}

// updateMutatingWebhookConfig updates the clientConfig to use node IP URL and CA bundle
func updateMutatingWebhookConfig(config *admissionv1.MutatingWebhookConfiguration, webhookConfig WebhookConfig) error {
	for i := range config.Webhooks {
		webhook := &config.Webhooks[i]

		// Get the path from the service config
		if webhook.ClientConfig.Service == nil {
			return fmt.Errorf("webhook %s has no service config", webhook.Name)
		}

		path := webhook.ClientConfig.Service.Path

		// Replace service with URL
		webhook.ClientConfig.Service = nil
		url := fmt.Sprintf("https://%s:%d%s", webhookConfig.NodeIP, webhookPort, *path)
		webhook.ClientConfig.URL = &url
		webhook.ClientConfig.CABundle = webhookConfig.CABundle
	}

	return nil
}

// updateValidatingWebhookConfig updates the clientConfig to use node IP URL and CA bundle
func updateValidatingWebhookConfig(config *admissionv1.ValidatingWebhookConfiguration, webhookConfig WebhookConfig) error {
	for i := range config.Webhooks {
		webhook := &config.Webhooks[i]

		// Get the path from the service config
		if webhook.ClientConfig.Service == nil {
			return fmt.Errorf("webhook %s has no service config", webhook.Name)
		}

		path := webhook.ClientConfig.Service.Path

		// Replace service with URL
		webhook.ClientConfig.Service = nil
		url := fmt.Sprintf("https://%s:%d%s", webhookConfig.NodeIP, webhookPort, *path)
		webhook.ClientConfig.URL = &url
		webhook.ClientConfig.CABundle = webhookConfig.CABundle
	}

	return nil
}

// applyMutatingWebhookConfiguration creates or updates the mutating webhook configuration
func applyMutatingWebhookConfiguration(ctx context.Context, k8sClient client.Client, config *admissionv1.MutatingWebhookConfiguration) error {
	// Try to get existing configuration
	existing := &admissionv1.MutatingWebhookConfiguration{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: config.Name}, existing)
	if err != nil {
		// Create new if doesn't exist
		if err := k8sClient.Create(ctx, config); err != nil {
			return fmt.Errorf("failed to create mutating webhook configuration: %w", err)
		}
		return nil
	}

	// Update existing
	existing.Webhooks = config.Webhooks
	if err := k8sClient.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update mutating webhook configuration: %w", err)
	}

	return nil
}

// applyValidatingWebhookConfiguration creates or updates the validating webhook configuration
func applyValidatingWebhookConfiguration(ctx context.Context, k8sClient client.Client, config *admissionv1.ValidatingWebhookConfiguration) error {
	// Try to get existing configuration
	existing := &admissionv1.ValidatingWebhookConfiguration{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: config.Name}, existing)
	if err != nil {
		// Create new if doesn't exist
		if err := k8sClient.Create(ctx, config); err != nil {
			return fmt.Errorf("failed to create validating webhook configuration: %w", err)
		}
		return nil
	}

	// Update existing
	existing.Webhooks = config.Webhooks
	if err := k8sClient.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update validating webhook configuration: %w", err)
	}

	return nil
}
