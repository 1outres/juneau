package trace

import (
	"testing"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestBuildSessionSpec covers the CRD → daemon SessionSpec
// translation. Numeric fields must round-trip exactly so the BPF
// side sees the operator's intent.
func TestBuildSessionSpec(t *testing.T) {
	exp := time.Now().Add(time.Minute)
	ts := &juneauv1alpha1.TraceSession{
		ObjectMeta: metav1.ObjectMeta{Generation: 7},
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID:   42,
			Mode:      juneauv1alpha1.TraceModeActiveProbe,
			ExpiresAt: metav1.NewTime(exp),
			Capture: juneauv1alpha1.TraceCaptureConfig{
				Level:             juneauv1alpha1.TraceCaptureLevelVerbose,
				IncludePacketMeta: true,
				IncludeMapMiss:    true,
				IncludePolicy:     false,
				IncludeNAT:        true,
			},
			InitialTuples: []juneauv1alpha1.TraceTuple{
				{
					Scope:    juneauv1alpha1.TraceTupleScopeVPC,
					VPCID:    7,
					SrcIP:    "10.0.1.1",
					DstIP:    "10.0.2.2",
					DstPort:  443,
					Protocol: juneauv1alpha1.TraceProtocolTCP,
				},
			},
		},
	}

	spec, err := buildSessionSpec(ts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.TraceID != 42 {
		t.Fatalf("trace_id: %d", spec.TraceID)
	}
	if spec.Generation != 7 {
		t.Fatalf("generation: %d", spec.Generation)
	}
	if spec.Mode != 1 {
		t.Fatalf("mode: %d (want 1=active)", spec.Mode)
	}
	if spec.Level != LevelVerbose {
		t.Fatalf("level: %d", spec.Level)
	}
	wantFlags := CapturePacketMeta | CaptureMapMiss | CaptureNAT
	if spec.CaptureFlags != wantFlags {
		t.Fatalf("flags: %x (want %x)", spec.CaptureFlags, wantFlags)
	}
	if !spec.ExpiresAt.Equal(exp) {
		t.Fatalf("expiresAt: %v (want %v)", spec.ExpiresAt, exp)
	}
	if len(spec.Tuples) != 1 {
		t.Fatalf("tuples: %d", len(spec.Tuples))
	}
	tk := spec.Tuples[0]
	if tk.Scope != ScopeVPC || tk.VPCID != 7 || tk.Protocol != 6 || tk.DstPort != 443 {
		t.Fatalf("tuple: %+v", tk)
	}
	if tk.SrcIP != [4]byte{10, 0, 1, 1} {
		t.Fatalf("src: %v", tk.SrcIP)
	}
}

func TestBuildSessionSpecObserveOnlyDefaultsLevel(t *testing.T) {
	ts := &juneauv1alpha1.TraceSession{
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID: 1,
			Mode:    juneauv1alpha1.TraceModeObserveOnly,
			ExpiresAt: metav1.NewTime(time.Now().Add(time.Minute)),
		},
	}
	spec, err := buildSessionSpec(ts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.Mode != 0 {
		t.Fatalf("mode: %d (want 0=observe)", spec.Mode)
	}
	if spec.Level != LevelDecision {
		t.Fatalf("level default: %d (want %d)", spec.Level, LevelDecision)
	}
}
