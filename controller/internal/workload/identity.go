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

// Package workload derives stable allocation identities from the workload
// that owns a pod. A pod names its workload with the allocation-identity
// annotation; a KubeVirt virt-launcher pod without it gets one from its
// VirtualMachine; any other pod is its own workload and gets one from its
// name.
package workload

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const identityPrefixPod = "pod."

// AllocationIdentity returns the stable identity of the workload behind a
// pod. The pod's PodAnnotationAllocationIdentity comes first. A pod without
// it gets the identity of its KubeVirt VirtualMachine, and any other pod
// gets "pod." followed by its name, so its addresses follow the pod name.
// An annotation that cannot serve as an identity is an error, and so is a
// pod whose name cannot form one.
func AllocationIdentity(pod *corev1.Pod) (string, error) {
	if pod == nil {
		return "", nil
	}
	identity, set, errs := juneauv1alpha1.PodAllocationIdentity(pod.Annotations)
	if len(errs) > 0 {
		return "", fmt.Errorf("read the allocation identity of pod %s/%s: %w", pod.Namespace, pod.Name, errs.ToAggregate())
	}
	if set {
		return identity, nil
	}
	if identity := kubeVirtAllocationIdentity(pod); identity != "" {
		return identity, nil
	}
	return podNameAllocationIdentity(pod)
}

// podNameAllocationIdentity names a pod that no workload claims after the
// pod itself. A pod name is a DNS-1123 subdomain already, but the prefix can
// push a very long one past the limit.
func podNameAllocationIdentity(pod *corev1.Pod) (string, error) {
	if pod.Name == "" {
		return "", fmt.Errorf("derive the allocation identity of a pod in namespace %q: the pod has no name", pod.Namespace)
	}
	identity := identityPrefixPod + pod.Name
	if errs := juneauv1alpha1.ValidateAllocationIdentity(identity, field.NewPath("metadata", "name")); len(errs) > 0 {
		return "", fmt.Errorf("derive the allocation identity of pod %s/%s from its name: %w", pod.Namespace, pod.Name, errs.ToAggregate())
	}
	return identity, nil
}
