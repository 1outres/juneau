package svcpolicy

import (
	"reflect"
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
		{"kubernetes Service is no longer implicitly shared",
			makeSvc("default", "kubernetes", nil), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsShared(tc.svc); got != tc.want {
				t.Errorf("IsShared = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAllowedConsumerVpcs(t *testing.T) {
	tests := []struct {
		name string
		ann  map[string]string
		want []string
	}{
		{"absent", nil, nil},
		{"empty value", map[string]string{AnnotationAllowedConsumerVpcs: ""}, []string{}},
		{"single", map[string]string{AnnotationAllowedConsumerVpcs: "default"}, []string{"default"}},
		{"comma-separated with whitespace",
			map[string]string{AnnotationAllowedConsumerVpcs: " default , vpc-a , "},
			[]string{"default", "vpc-a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AllowedConsumerVpcs(makeSvc("ns", "svc", tc.ann))
			if !reflect.DeepEqual(normalise(got), normalise(tc.want)) {
				t.Errorf("AllowedConsumerVpcs = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// normalise treats nil and empty slices as equivalent for assertion
// purposes — both mean "no ACL configured" to ResolvableFrom.
func normalise(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func TestIsAllowedConsumer(t *testing.T) {
	tests := []struct {
		name      string
		svc       *corev1.Service
		callerVpc string
		want      bool
	}{
		{"no ACL → allow",
			makeSvc("ns", "svc", map[string]string{AnnotationShared: "true"}),
			"vpc-a", true},
		{"caller in ACL → allow",
			makeSvc("ns", "svc", map[string]string{AnnotationShared: "true", AnnotationAllowedConsumerVpcs: "default,vpc-a"}),
			"vpc-a", true},
		{"caller not in ACL → deny",
			makeSvc("ns", "svc", map[string]string{AnnotationShared: "true", AnnotationAllowedConsumerVpcs: "default"}),
			"vpc-a", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAllowedConsumer(tc.svc, tc.callerVpc); got != tc.want {
				t.Errorf("IsAllowedConsumer = %v, want %v", got, tc.want)
			}
		})
	}
}

func strPtr(s string) *string { return &s }

func TestIsJuneauLoadBalancer(t *testing.T) {
	tests := []struct {
		name string
		svc  *corev1.Service
		want bool
	}{
		{"nil", nil, false},
		{"non-LB type", &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, LoadBalancerClass: strPtr(LoadBalancerClass)}}, false},
		{"LB without class", &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}}, false},
		{"LB with foreign class", &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, LoadBalancerClass: strPtr("metallb.io/external")}}, false},
		{"LB with juneau class", &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, LoadBalancerClass: strPtr(LoadBalancerClass)}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsJuneauLoadBalancer(tc.svc); got != tc.want {
				t.Errorf("IsJuneauLoadBalancer = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLBExternalNetwork(t *testing.T) {
	tests := []struct {
		name string
		ann  map[string]string
		want string
	}{
		{"absent", nil, ""},
		{"empty", map[string]string{AnnotationLBExternalNetwork: ""}, ""},
		{"with value", map[string]string{AnnotationLBExternalNetwork: "ext-net"}, "ext-net"},
		{"trims whitespace", map[string]string{AnnotationLBExternalNetwork: "  ext-net  "}, "ext-net"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := LBExternalNetwork(makeSvc("ns", "svc", tc.ann)); got != tc.want {
				t.Errorf("LBExternalNetwork = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLBRequestedIP(t *testing.T) {
	tests := []struct {
		name string
		ann  map[string]string
		want string
	}{
		{"absent", nil, ""},
		{"empty", map[string]string{AnnotationLBRequestedIP: ""}, ""},
		{"with value", map[string]string{AnnotationLBRequestedIP: "10.0.0.5"}, "10.0.0.5"},
		{"trims whitespace", map[string]string{AnnotationLBRequestedIP: "  10.0.0.5\t"}, "10.0.0.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := LBRequestedIP(makeSvc("ns", "svc", tc.ann)); got != tc.want {
				t.Errorf("LBRequestedIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolvableFrom(t *testing.T) {
	type tcase struct {
		name   string
		svc    *corev1.Service
		caller CallerVpc
		want   bool
	}
	tests := []tcase{
		{
			name:   "caller without ServiceEnabled never resolves",
			svc:    makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default"}),
			caller: CallerVpc{Name: "default", ServiceEnabled: false},
			want:   false,
		},
		{
			name:   "same VPC + ServiceEnabled resolves without consume",
			svc:    makeSvc("ns", "svc", map[string]string{AnnotationVpc: "tenant-x"}),
			caller: CallerVpc{Name: "tenant-x", ServiceEnabled: true, Consume: false},
			want:   true,
		},
		{
			name:   "different VPC, not shared, denied",
			svc:    makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default"}),
			caller: CallerVpc{Name: "tenant-x", ServiceEnabled: true, Consume: true},
			want:   false,
		},
		{
			name:   "different VPC, shared, no ACL, consume → allowed",
			svc:    makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default", AnnotationShared: "true"}),
			caller: CallerVpc{Name: "tenant-x", ServiceEnabled: true, Consume: true},
			want:   true,
		},
		{
			name:   "different VPC, shared, no consume → denied",
			svc:    makeSvc("ns", "svc", map[string]string{AnnotationShared: "true"}),
			caller: CallerVpc{Name: "tenant-x", ServiceEnabled: true, Consume: false},
			want:   false,
		},
		{
			name:   "different VPC, shared, ACL allow → allowed",
			svc:    makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default", AnnotationShared: "true", AnnotationAllowedConsumerVpcs: "tenant-x"}),
			caller: CallerVpc{Name: "tenant-x", ServiceEnabled: true, Consume: true},
			want:   true,
		},
		{
			name:   "different VPC, shared, ACL deny → denied",
			svc:    makeSvc("ns", "svc", map[string]string{AnnotationVpc: "default", AnnotationShared: "true", AnnotationAllowedConsumerVpcs: "vpc-a"}),
			caller: CallerVpc{Name: "tenant-x", ServiceEnabled: true, Consume: true},
			want:   false,
		},
		{
			name:   "kubernetes Service is no longer implicitly shared",
			svc:    makeSvc("default", "kubernetes", nil),
			caller: CallerVpc{Name: "tenant-x", ServiceEnabled: true, Consume: true},
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolvableFrom(tc.svc, tc.caller); got != tc.want {
				t.Errorf("ResolvableFrom = %v, want %v", got, tc.want)
			}
		})
	}
}
