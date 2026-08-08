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
	"k8s.io/apimachinery/pkg/runtime/schema"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
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

// KubeVirtVirtualMachineGVK is the object that owns a virtual machine's
// address. The manager also uses it to decide whether the cluster serves
// the kind before it watches it.
var KubeVirtVirtualMachineGVK = schema.GroupVersionKind{
	Group:   "kubevirt.io",
	Version: "v1",
	Kind:    "VirtualMachine",
}

// AllocationIdentity returns the stable identity of the virtual machine
// behind a virt-launcher pod. KubeVirt gives the pod a new name on every
// restart, so the address has to follow the virtual machine instead. It
// returns an empty string for pods KubeVirt does not manage, and the caller
// keeps using the pod name.
func AllocationIdentity(pod *corev1.Pod) string {
	name := virtualMachineName(pod)
	if name == "" {
		return ""
	}
	return identityPrefixKubeVirt + name
}

// RetainReference returns the VirtualMachine that must keep the address of
// a virt-launcher pod. A stopped virtual machine has no pod at all, so the
// reservation has to hang off the machine itself. It returns nil for pods
// KubeVirt does not manage, whose address is released with the pod.
func RetainReference(pod *corev1.Pod) *juneauv1alpha1.RetainReference {
	name := virtualMachineName(pod)
	if name == "" {
		return nil
	}
	return &juneauv1alpha1.RetainReference{
		APIVersion: KubeVirtVirtualMachineGVK.GroupVersion().String(),
		Kind:       KubeVirtVirtualMachineGVK.Kind,
		Namespace:  pod.Namespace,
		Name:       name,
	}
}

// virtualMachineName reads the VirtualMachine name off a virt-launcher pod,
// returning an empty string for every other pod.
func virtualMachineName(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	if pod.Labels[labelKubeVirtComponent] != valueVirtLauncher {
		return ""
	}
	return pod.Labels[labelVirtualMachineName]
}
