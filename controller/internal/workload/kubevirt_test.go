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
)

func TestAllocationIdentity(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{
			name: "virt-launcher pod of a named virtual machine",
			labels: map[string]string{
				"kubevirt.io":         "virt-launcher",
				"vm.kubevirt.io/name": "web-0",
			},
			want: "vmi.web-0",
		},
		{
			name: "virt-launcher pod without a virtual machine name",
			labels: map[string]string{
				"kubevirt.io": "virt-launcher",
			},
			want: "",
		},
		{
			name: "virt-launcher pod with an empty virtual machine name",
			labels: map[string]string{
				"kubevirt.io":         "virt-launcher",
				"vm.kubevirt.io/name": "",
			},
			want: "",
		},
		{
			name: "other kubevirt component",
			labels: map[string]string{
				"kubevirt.io":         "virt-handler",
				"vm.kubevirt.io/name": "web-0",
			},
			want: "",
		},
		{
			name: "pod that carries only the virtual machine name label",
			labels: map[string]string{
				"vm.kubevirt.io/name": "web-0",
			},
			want: "",
		},
		{
			name:   "pod unrelated to kubevirt",
			labels: map[string]string{"app": "web"},
			want:   "",
		},
		{
			name:   "pod without labels",
			labels: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "virt-launcher-web-0-abcde", Labels: tt.labels}}
			if got := AllocationIdentity(pod); got != tt.want {
				t.Errorf("AllocationIdentity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAllocationIdentityNilPod(t *testing.T) {
	if got := AllocationIdentity(nil); got != "" {
		t.Errorf("AllocationIdentity(nil) = %q, want %q", got, "")
	}
}
