package webhookapply

import (
	"bytes"
	"context"
	"fmt"

	admv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Apply reads embedded webhook manifests, rewrites names and clientConfig (URL + CA),
// and creates/updates them in the cluster.
func Apply(ctx context.Context, cfg *rest.Config, nodeName, namespace, caSecretName, namePrefix string, manifests []byte) error {
	logger := log.FromContext(ctx)

	if nodeName == "" {
		logger.Info("NODE_NAME is empty; skipping webhook configuration apply")
		return nil
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create clientset: %w", err)
	}

	node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", nodeName, err)
	}
	nodeIP, err := pickNodeIP(node)
	if err != nil {
		return fmt.Errorf("pick node IP: %w", err)
	}

	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, caSecretName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logger.Info("CA secret not found; skipping webhook configuration apply", "secret", caSecretName, "namespace", namespace)
			return nil
		}
		return fmt.Errorf("get CA secret: %w", err)
	}

	caBundle := secret.Data["ca.crt"]
	if len(caBundle) == 0 {
		logger.Info("CA bundle missing in secret; skipping webhook configuration apply", "secret", caSecretName, "namespace", namespace)
		return nil
	}

	scheme := runtime.NewScheme()
	if err := admv1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("add admissionregistration to scheme: %w", err)
	}
	decoder := serializer.NewCodecFactory(scheme).UniversalDeserializer()
	docDecoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifests), 4096)

	for {
		var raw runtime.RawExtension
		if err := docDecoder.Decode(&raw); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return fmt.Errorf("decode manifest: %w", err)
		}
		if len(raw.Raw) == 0 {
			continue
		}

		obj, gvk, err := decoder.Decode(raw.Raw, nil, nil)
		if err != nil {
			return fmt.Errorf("decode object: %w", err)
		}

		switch o := obj.(type) {
		case *admv1.MutatingWebhookConfiguration:
			prepareMutating(o, nodeIP, caBundle, namePrefix)
			if err := upsertMutating(ctx, clientset, o); err != nil {
				return fmt.Errorf("apply mutating webhook %s: %w", o.Name, err)
			}
		case *admv1.ValidatingWebhookConfiguration:
			prepareValidating(o, nodeIP, caBundle, namePrefix)
			if err := upsertValidating(ctx, clientset, o); err != nil {
				return fmt.Errorf("apply validating webhook %s: %w", o.Name, err)
			}
		default:
			logger.Info("skipping unsupported GVK in embedded manifests", "gvk", gvk.String())
		}
	}

	return nil
}

func pickNodeIP(node *corev1.Node) (string, error) {
	var fallback string
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address, nil
		}
		if addr.Type == corev1.NodeExternalIP && fallback == "" {
			fallback = addr.Address
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no usable node IP on %s", node.Name)
}

func prepareMutating(obj *admv1.MutatingWebhookConfiguration, nodeIP string, caBundle []byte, prefix string) {
	obj.Name = prefix + obj.Name
	for i := range obj.Webhooks {
		path := ""
		if obj.Webhooks[i].ClientConfig.Service != nil {
			path = pointer.StringDeref(obj.Webhooks[i].ClientConfig.Service.Path, "")
		}
		url := fmt.Sprintf("https://%s:9443%s", nodeIP, path)
		obj.Webhooks[i].ClientConfig.Service = nil
		obj.Webhooks[i].ClientConfig.URL = pointer.String(url)
		obj.Webhooks[i].ClientConfig.CABundle = caBundle
	}
}

func prepareValidating(obj *admv1.ValidatingWebhookConfiguration, nodeIP string, caBundle []byte, prefix string) {
	obj.Name = prefix + obj.Name
	for i := range obj.Webhooks {
		path := ""
		if obj.Webhooks[i].ClientConfig.Service != nil {
			path = pointer.StringDeref(obj.Webhooks[i].ClientConfig.Service.Path, "")
		}
		url := fmt.Sprintf("https://%s:9443%s", nodeIP, path)
		obj.Webhooks[i].ClientConfig.Service = nil
		obj.Webhooks[i].ClientConfig.URL = pointer.String(url)
		obj.Webhooks[i].ClientConfig.CABundle = caBundle
	}
}

func upsertMutating(ctx context.Context, clientset *kubernetes.Clientset, obj *admv1.MutatingWebhookConfiguration) error {
	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	existing, err := client.Get(ctx, obj.Name, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			_, err = client.Create(ctx, obj, metav1.CreateOptions{})
			return err
		}
		return err
	}
	obj.ResourceVersion = existing.ResourceVersion
	_, err = client.Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func upsertValidating(ctx context.Context, clientset *kubernetes.Clientset, obj *admv1.ValidatingWebhookConfiguration) error {
	client := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	existing, err := client.Get(ctx, obj.Name, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			_, err = client.Create(ctx, obj, metav1.CreateOptions{})
			return err
		}
		return err
	}
	obj.ResourceVersion = existing.ResourceVersion
	_, err = client.Update(ctx, obj, metav1.UpdateOptions{})
	return err
}
