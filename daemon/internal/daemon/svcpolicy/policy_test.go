package svcpolicy

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeSvc(ns, name string, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: annotations,
		},
	}
}

func TestOwningVpc(t *testing.T) {
	tests := []struct {
		name string
		svc  *corev1.Service
		want string
	}{
		{"nil → default", nil, DefaultVpc},
		{"no annotation → default", makeSvc("foo", "bar", nil), DefaultVpc},
		{"empty annotation → default", makeSvc("foo", "bar", map[string]string{AnnotationVpc: ""}), DefaultVpc},
		{"annotated → name", makeSvc("foo", "bar", map[string]string{AnnotationVpc: "tenant-x"}), "tenant-x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := OwningVpc(tc.svc); got != tc.want {
				t.Errorf("OwningVpc = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsShared(t *testing.T) {
	tests := []struct {
		name string
		svc  *corev1.Service
		want bool
	}{
		{"nil", nil, false},
		{"plain", makeSvc("ns", "svc", nil), false},
		{"annotated true", makeSvc("ns", "svc", map[string]string{AnnotationShared: "true"}), true},
		{"annotated false", makeSvc("ns", "svc", map[string]string{AnnotationShared: "false"}), false},
		{"kubernetes implicit", makeSvc(KubernetesNamespace, KubernetesName, nil), true},
		{"other svc named kubernetes in non-default ns is not implicit",
			makeSvc("other-ns", KubernetesName, nil), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsShared(tc.svc); got != tc.want {
				t.Errorf("IsShared = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvableFrom(t *testing.T) {
	type tcase struct {
		name                string
		svc                 *corev1.Service
		callerVpc           string
		callerEnableService bool
		want                bool
	}
	tests := []tcase{
		{
			name:                "caller without EnableService never resolves",
			svc:                 makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default"}),
			callerVpc:           "default",
			callerEnableService: false,
			want:                false,
		},
		{
			name:                "same VPC + EnableService resolves",
			svc:                 makeSvc("ns", "svc", map[string]string{AnnotationVpc: "tenant-x"}),
			callerVpc:           "tenant-x",
			callerEnableService: true,
			want:                true,
		},
		{
			name:                "different VPC, not shared, denied",
			svc:                 makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default"}),
			callerVpc:           "tenant-x",
			callerEnableService: true,
			want:                false,
		},
		{
			name:                "different VPC, shared, allowed",
			svc:                 makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default", AnnotationShared: "true"}),
			callerVpc:           "tenant-x",
			callerEnableService: true,
			want:                true,
		},
		{
			name:                "kubernetes Service is implicitly shared",
			svc:                 makeSvc(KubernetesNamespace, KubernetesName, nil),
			callerVpc:           "tenant-x",
			callerEnableService: true,
			want:                true,
		},
		{
			name:                "shared but caller has no EnableService → still denied",
			svc:                 makeSvc("ns", "svc", map[string]string{AnnotationShared: "true"}),
			callerVpc:           "tenant-x",
			callerEnableService: false,
			want:                false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolvableFrom(tc.svc, tc.callerVpc, tc.callerEnableService); got != tc.want {
				t.Errorf("ResolvableFrom = %v, want %v", got, tc.want)
			}
		})
	}
}
