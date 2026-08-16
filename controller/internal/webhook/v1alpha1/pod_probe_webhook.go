/*
Copyright 2026.

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

package v1alpha1

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	probeconfig "github.com/1outres/juneau/controller/pkg/probe"
)

const (
	probeWebhookPath = "/mutate--v1-pod-probes"
	probeWebhookName = "mprobe-pod-juneau-loutres-me.kb.io"
)

// When probe rewriting is enabled at controller startup, the generated
// configuration is further scoped to Juneau Subnet Pods with a CEL
// matchCondition in webhookapply.prepareMutating. controller-gen does not
// currently expose matchConditions in its webhook marker.
// +kubebuilder:webhook:path=/mutate--v1-pod-probes,mutating=true,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=mprobe-pod-juneau-loutres-me.kb.io,admissionReviewVersions=v1,reinvocationPolicy=IfNeeded,timeoutSeconds=5

func setupPodProbeWebhookWithManager(mgr ctrl.Manager, proxyPort int32) error {
	defaulter := &PodProbeDefaulter{Reader: mgr.GetClient(), ProxyPort: proxyPort}
	mgr.GetWebhookServer().Register(
		probeWebhookPath,
		admission.WithCustomDefaulter(mgr.GetScheme(), &corev1.Pod{}, defaulter),
	)
	return nil
}

// PodProbeDefaulter rewrites kubelet network probes to a node-local HTTP
// endpoint. The Juneau daemon executes the original probe from the target
// Pod's network namespace. This is deliberately an opt-in compatibility
// mode and does not claim node-to-Pod datapath equivalence.
type PodProbeDefaulter struct {
	client.Reader
	ProxyPort int32
}

var _ webhook.CustomDefaulter = &PodProbeDefaulter{}

func (d *PodProbeDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return fmt.Errorf("expected a Pod object but got %T", obj)
	}
	subnetName := pod.Annotations[PodAnnotationSubnet]
	if subnetName == "" || subnetName == dnsPodSubnetDefault || pod.Spec.HostNetwork {
		return nil
	}
	if _, isMirror := pod.Annotations["kubernetes.io/config.mirror"]; isMirror {
		return nil
	}
	if pod.Spec.OS != nil && pod.Spec.OS.Name == corev1.Windows {
		return nil
	}

	var subnet juneauv1alpha1.Subnet
	if err := d.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
		return fmt.Errorf("resolve probe rewrite Subnet %q: %w", subnetName, err)
	}
	if subnet.Spec.Vpc == defaultVpcName {
		return nil
	}
	port := d.ProxyPort
	if port == 0 {
		port = probeconfig.DefaultProxyPort
	}
	return rewriteNetworkProbes(pod, port)
}

func rewriteNetworkProbes(pod *corev1.Pod, agentPort int32) error {
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	version := pod.Annotations[probeconfig.AnnotationRewriteVersion]
	if version != "" && version != probeconfig.RewriteVersion {
		return fmt.Errorf("unsupported probe rewrite version %q", version)
	}
	configs, err := probeconfig.Parse(pod.Annotations[probeconfig.AnnotationConfigs])
	if err != nil {
		return err
	}

	changed, err := rewriteProbeContainers(pod.Spec.InitContainers, configs, agentPort)
	if err != nil {
		return err
	}
	regularChanged, err := rewriteProbeContainers(pod.Spec.Containers, configs, agentPort)
	if err != nil {
		return err
	}
	changed = changed || regularChanged
	if !changed {
		if version != "" && len(configs) == 0 {
			return fmt.Errorf("probe rewrite marker exists but no probe configs were found")
		}
		return nil
	}
	encoded, err := probeconfig.Encode(configs)
	if err != nil {
		return err
	}
	pod.Annotations[probeconfig.AnnotationRewriteVersion] = probeconfig.RewriteVersion
	pod.Annotations[probeconfig.AnnotationConfigs] = encoded
	return nil
}

func rewriteProbeContainers(containers []corev1.Container, configs probeconfig.Configs, agentPort int32) (bool, error) {
	changed := false
	for i := range containers {
		container := &containers[i]
		for _, item := range []*corev1.Probe{container.StartupProbe, container.ReadinessProbe, container.LivenessProbe} {
			rewritten, err := rewriteNetworkProbe(container, item, configs, agentPort)
			if err != nil {
				return false, fmt.Errorf("rewrite probe for container %q: %w", container.Name, err)
			}
			changed = changed || rewritten
		}
	}
	return changed, nil
}

func rewriteNetworkProbe(container *corev1.Container, item *corev1.Probe, configs probeconfig.Configs, agentPort int32) (bool, error) {
	if item == nil || item.Exec != nil || isAgentProbe(item, configs, agentPort) || hasExplicitProbeHost(item) {
		return false, nil
	}
	config := probeconfig.Config{Timeout: item.TimeoutSeconds}
	switch {
	case item.HTTPGet != nil:
		config.Type = "http"
		config.Path = item.HTTPGet.Path
		config.Scheme = string(item.HTTPGet.Scheme)
		for _, header := range item.HTTPGet.HTTPHeaders {
			config.Headers = append(config.Headers, probeconfig.Header{Name: header.Name, Value: header.Value})
		}
		port, err := resolveProbePort(container, item.HTTPGet.Port)
		if err != nil {
			return false, err
		}
		config.Port = port
	case item.TCPSocket != nil:
		config.Type = "tcp"
		port, err := resolveProbePort(container, item.TCPSocket.Port)
		if err != nil {
			return false, err
		}
		config.Port = port
	case item.GRPC != nil:
		config.Type = "grpc"
		config.Port = item.GRPC.Port
		if item.GRPC.Service != nil {
			config.GRPCService = *item.GRPC.Service
		}
	default:
		return false, nil
	}
	token, err := newProbeToken(configs)
	if err != nil {
		return false, err
	}
	configs[token] = config
	item.ProbeHandler = corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
		Host:   "127.0.0.1",
		Port:   intstr.FromInt32(agentPort),
		Path:   probeconfig.EndpointPathPrefix + token,
		Scheme: corev1.URISchemeHTTP,
	}}
	return true, nil
}

func isAgentProbe(item *corev1.Probe, configs probeconfig.Configs, agentPort int32) bool {
	if item == nil || item.HTTPGet == nil || item.HTTPGet.Host != "127.0.0.1" || item.HTTPGet.Port.IntVal != agentPort {
		return false
	}
	token := strings.TrimPrefix(item.HTTPGet.Path, probeconfig.EndpointPathPrefix)
	if token == item.HTTPGet.Path || token == "" {
		return false
	}
	_, ok := configs[token]
	return ok
}

// An explicit host points the probe at an address that is not the Pod itself,
// so rewriting it would change what the probe checks. GRPCAction has no host
// field, and kubelet keeps reaching the given host directly.
func hasExplicitProbeHost(item *corev1.Probe) bool {
	switch {
	case item.HTTPGet != nil:
		return item.HTTPGet.Host != ""
	case item.TCPSocket != nil:
		return item.TCPSocket.Host != ""
	default:
		return false
	}
}

func newProbeToken(configs probeconfig.Configs) (string, error) {
	for {
		data := make([]byte, 16)
		if _, err := rand.Read(data); err != nil {
			return "", fmt.Errorf("generate probe token: %w", err)
		}
		token := hex.EncodeToString(data)
		if _, exists := configs[token]; !exists {
			return token, nil
		}
	}
}

func resolveProbePort(container *corev1.Container, port intstr.IntOrString) (int32, error) {
	if port.Type == intstr.Int {
		if port.IntVal < 1 || port.IntVal > 65535 {
			return 0, fmt.Errorf("invalid probe port %d", port.IntVal)
		}
		return port.IntVal, nil
	}
	for _, candidate := range container.Ports {
		if candidate.Name == port.StrVal {
			return candidate.ContainerPort, nil
		}
	}
	return 0, fmt.Errorf("named probe port %q is not declared by the container", port.StrVal)
}
