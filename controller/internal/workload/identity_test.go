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
