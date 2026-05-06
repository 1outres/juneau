package svcpolicy

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ptr[T any](v T) *T { return &v }

func makeSelectionSvc(spec corev1.ServiceSpec) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "svc"},
		Spec:       spec,
	}
}

func TestSelectionPolicyOf_Default(t *testing.T) {
	got := SelectionPolicyOf(makeSelectionSvc(corev1.ServiceSpec{}))
	if got.InternalLocal {
		t.Errorf("default InternalLocal should be false, got true")
	}
	if got.Affinity.Mode != AffinityNone {
		t.Errorf("default Affinity.Mode = %d, want %d", got.Affinity.Mode, AffinityNone)
	}
	if got.Affinity.Timeout != 0 {
		t.Errorf("default Affinity.Timeout = %v, want 0", got.Affinity.Timeout)
	}
	if !got.IsClusterInternal() {
		t.Errorf("default IsClusterInternal should be true")
	}
}

func TestSelectionPolicyOf_Nil(t *testing.T) {
	got := SelectionPolicyOf(nil)
	if got != (BackendSelectionPolicy{}) {
		t.Errorf("nil Service should yield zero-value policy, got %+v", got)
	}
}

func TestSelectionPolicyOf_InternalTrafficPolicy(t *testing.T) {
	tests := []struct {
		name string
		spec corev1.ServiceSpec
		want bool
	}{
		{
			name: "explicit Cluster",
			spec: corev1.ServiceSpec{InternalTrafficPolicy: ptr(corev1.ServiceInternalTrafficPolicyCluster)},
			want: false,
		},
		{
			name: "explicit Local",
			spec: corev1.ServiceSpec{InternalTrafficPolicy: ptr(corev1.ServiceInternalTrafficPolicyLocal)},
			want: true,
		},
		{
			name: "unset → Cluster",
			spec: corev1.ServiceSpec{},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectionPolicyOf(makeSelectionSvc(tc.spec))
			if got.InternalLocal != tc.want {
				t.Errorf("InternalLocal = %v, want %v", got.InternalLocal, tc.want)
			}
		})
	}
}

func TestSelectionPolicyOf_Affinity(t *testing.T) {
	tests := []struct {
		name        string
		spec        corev1.ServiceSpec
		wantMode    AffinityMode
		wantTimeout time.Duration
	}{
		{
			name:        "no affinity",
			spec:        corev1.ServiceSpec{SessionAffinity: corev1.ServiceAffinityNone},
			wantMode:    AffinityNone,
			wantTimeout: 0,
		},
		{
			name: "ClientIP with explicit 600s",
			spec: corev1.ServiceSpec{
				SessionAffinity: corev1.ServiceAffinityClientIP,
				SessionAffinityConfig: &corev1.SessionAffinityConfig{
					ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: ptr(int32(600))},
				},
			},
			wantMode:    AffinityClientIP,
			wantTimeout: 600 * time.Second,
		},
		{
			name:        "ClientIP without config → default 3h",
			spec:        corev1.ServiceSpec{SessionAffinity: corev1.ServiceAffinityClientIP},
			wantMode:    AffinityClientIP,
			wantTimeout: DefaultClientIPAffinityTimeout,
		},
		{
			name: "ClientIP with nil ClientIPConfig → default",
			spec: corev1.ServiceSpec{
				SessionAffinity:       corev1.ServiceAffinityClientIP,
				SessionAffinityConfig: &corev1.SessionAffinityConfig{},
			},
			wantMode:    AffinityClientIP,
			wantTimeout: DefaultClientIPAffinityTimeout,
		},
		{
			name: "ClientIP with TimeoutSeconds=0 → default",
			spec: corev1.ServiceSpec{
				SessionAffinity: corev1.ServiceAffinityClientIP,
				SessionAffinityConfig: &corev1.SessionAffinityConfig{
					ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: ptr(int32(0))},
				},
			},
			wantMode:    AffinityClientIP,
			wantTimeout: DefaultClientIPAffinityTimeout,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectionPolicyOf(makeSelectionSvc(tc.spec))
			if got.Affinity.Mode != tc.wantMode {
				t.Errorf("Affinity.Mode = %d, want %d", got.Affinity.Mode, tc.wantMode)
			}
			if got.Affinity.Timeout != tc.wantTimeout {
				t.Errorf("Affinity.Timeout = %v, want %v", got.Affinity.Timeout, tc.wantTimeout)
			}
		})
	}
}

func TestSelectionPolicyOf_Combined(t *testing.T) {
	spec := corev1.ServiceSpec{
		InternalTrafficPolicy: ptr(corev1.ServiceInternalTrafficPolicyLocal),
		SessionAffinity:       corev1.ServiceAffinityClientIP,
		SessionAffinityConfig: &corev1.SessionAffinityConfig{
			ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: ptr(int32(120))},
		},
	}
	got := SelectionPolicyOf(makeSelectionSvc(spec))
	if !got.InternalLocal {
		t.Errorf("InternalLocal should be true under iTP=Local")
	}
	if got.IsClusterInternal() {
		t.Errorf("IsClusterInternal should be false under iTP=Local")
	}
	if got.Affinity.Mode != AffinityClientIP || got.Affinity.Timeout != 120*time.Second {
		t.Errorf("Affinity = %+v, want {ClientIP, 120s}", got.Affinity)
	}
}
