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

package workload

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func TestAllocationIdentityFromAnnotation(t *testing.T) {
	tests := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		want        string
		wantErr     bool
	}{
		{
			name:        "plain pod with the annotation",
			annotations: map[string]string{juneauv1alpha1.PodAnnotationAllocationIdentity: "router"},
			want:        "router",
		},
		{
			name: "virt-launcher pod with the annotation",
			labels: map[string]string{
				"kubevirt.io":         "virt-launcher",
				"vm.kubevirt.io/name": "web-0",
			},
			annotations: map[string]string{juneauv1alpha1.PodAnnotationAllocationIdentity: "vmi.vm-web-0"},
			want:        "vmi.vm-web-0",
		},
		{
			name:        "empty annotation",
			annotations: map[string]string{juneauv1alpha1.PodAnnotationAllocationIdentity: ""},
			wantErr:     true,
		},
		{
			name: "invalid annotation on a virt-launcher pod",
			labels: map[string]string{
				"kubevirt.io":         "virt-launcher",
				"vm.kubevirt.io/name": "web-0",
			},
			annotations: map[string]string{juneauv1alpha1.PodAnnotationAllocationIdentity: "Not_Valid"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace:   "default",
				Name:        "router-abcde",
				Labels:      tt.labels,
				Annotations: tt.annotations,
			}}
			got, err := AllocationIdentity(pod)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("AllocationIdentity() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AllocationIdentity() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("AllocationIdentity() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The annotation names the identity only. The address of a virt-launcher
// pod still has to outlive the pod for as long as its VirtualMachine is
// there.
func TestRetainReferenceIgnoresTheAnnotation(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "virt-launcher-web-0-abcde",
		Labels: map[string]string{
			"kubevirt.io":         "virt-launcher",
			"vm.kubevirt.io/name": "web-0",
		},
		Annotations: map[string]string{juneauv1alpha1.PodAnnotationAllocationIdentity: "vmi.vm-web-0"},
	}}
	got := RetainReference(pod)
	if got == nil || got.Name != "web-0" {
		t.Fatalf("RetainReference() = %+v, want the VirtualMachine web-0", got)
	}

	plain := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "default",
		Name:        "router",
		Annotations: map[string]string{juneauv1alpha1.PodAnnotationAllocationIdentity: "router"},
	}}
	if got := RetainReference(plain); got != nil {
		t.Errorf("RetainReference() = %+v, want nil for a pod KubeVirt does not manage", got)
	}
}

// A pod with neither the annotation nor the KubeVirt label is named by the
// pod itself, so every NIC of every workload has an identity.
func TestAllocationIdentityDefaultsToThePodName(t *testing.T) {
	tests := []struct {
		name    string
		podName string
		want    string
	}{
		{name: "bare pod", podName: "ctr-web", want: "pod.ctr-web"},
		{name: "replica set member", podName: "pool-7d9f8b6c4-x2k9z", want: "pod.pool-7d9f8b6c4-x2k9z"},
		{name: "pod name with dots", podName: "web.example", want: "pod.web.example"},
		{name: "longest name that fits", podName: strings.Repeat("a", 249), want: "pod." + strings.Repeat("a", 249)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: tt.podName}}
			got, err := AllocationIdentity(pod)
			if err != nil {
				t.Fatalf("AllocationIdentity() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("AllocationIdentity() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The identity becomes part of an AllocationLease name, so a pod name that
// pushes "pod.<name>" past the DNS-1123 subdomain limit has no identity.
// Falling back to an empty identity would change the lease key silently.
func TestAllocationIdentityRejectsAPodNameThatCannotFit(t *testing.T) {
	tests := []struct {
		name    string
		podName string
	}{
		{name: "one character too long", podName: strings.Repeat("a", 250)},
		{name: "longest valid pod name", podName: strings.Repeat("a", 253)},
		{name: "pod without a name", podName: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: tt.podName}}
			if got, err := AllocationIdentity(pod); err == nil {
				t.Errorf("AllocationIdentity() = %q, want an error", got)
			}
		})
	}
}

// The annotation and the KubeVirt label win over the pod name, and a pod
// name that cannot fit does not matter when either of them names the
// workload.
func TestAllocationIdentityPodNameIsTheLastResort(t *testing.T) {
	longName := strings.Repeat("a", 253)

	annotated := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "default",
		Name:        longName,
		Annotations: map[string]string{juneauv1alpha1.PodAnnotationAllocationIdentity: "router"},
	}}
	if got, err := AllocationIdentity(annotated); err != nil || got != "router" {
		t.Errorf("AllocationIdentity(annotated) = %q, %v, want router", got, err)
	}

	virtLauncher := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      longName,
		Labels: map[string]string{
			"kubevirt.io":         "virt-launcher",
			"vm.kubevirt.io/name": "web-0",
		},
	}}
	if got, err := AllocationIdentity(virtLauncher); err != nil || got != "vmi.web-0" {
		t.Errorf("AllocationIdentity(virt-launcher) = %q, %v, want vmi.web-0", got, err)
	}
}
