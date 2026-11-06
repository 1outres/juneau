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
// VirtualMachine.
package workload

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// AllocationIdentity returns the stable identity of the workload behind a
// pod. The pod's PodAnnotationAllocationIdentity comes first. A pod without
// it gets the identity of its KubeVirt VirtualMachine, and any other pod
// gets an empty string, so its addresses follow the pod name. An annotation
// that cannot serve as an identity is an error.
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
	return kubeVirtAllocationIdentity(pod), nil
}
