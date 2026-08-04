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
// that owns a pod. Only KubeVirt is supported today.
package workload

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	labelKubeVirtComponent = "kubevirt.io"
	valueVirtLauncher      = "virt-launcher"

	// KubeVirt sets this label on the virt-launcher pod itself, so it is
	// there even when the VirtualMachine template does not carry it. The
	// value is the VirtualMachine name, which survives a restart. The pod
	// name, the VirtualMachineInstance UID and the owner references do not.
	labelVirtualMachineName = "vm.kubevirt.io/name"

	identityPrefixKubeVirt = "vmi."
)

// AllocationIdentity returns the stable identity of the virtual machine
// behind a virt-launcher pod. KubeVirt gives the pod a new name on every
// restart, so the address has to follow the virtual machine instead. It
// returns an empty string for pods KubeVirt does not manage, and the caller
// keeps using the pod name.
func AllocationIdentity(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	if pod.Labels[labelKubeVirtComponent] != valueVirtLauncher {
		return ""
	}
	name := pod.Labels[labelVirtualMachineName]
	if name == "" {
		return ""
	}
	return identityPrefixKubeVirt + name
}
