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

package v1alpha1

import (
	"context"
	"strings"
	"testing"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func validTraceSession() *juneauv1alpha1.TraceSession {
	return &juneauv1alpha1.TraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "trace-test"},
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID:   1,
			Mode:      juneauv1alpha1.TraceModeObserveOnly,
			ExpiresAt: metav1.NewTime(time.Now().Add(time.Minute)),
			Source: juneauv1alpha1.TraceEndpoint{
				PodRef: &juneauv1alpha1.TracePodReference{
					Namespace: "default", Name: "client",
				},
			},
			Destination: juneauv1alpha1.TraceEndpoint{
				ServiceRef: &juneauv1alpha1.TraceServiceReference{
					Namespace: "default", Name: "api",
				},
				Protocol: juneauv1alpha1.TraceProtocolTCP,
				Port:     443,
			},
			InitialTuples: []juneauv1alpha1.TraceTuple{
				{
					Scope:    juneauv1alpha1.TraceTupleScopeVPC,
					VPCID:    1,
					SrcIP:    "10.0.1.10",
					DstIP:    "10.96.0.10",
					DstPort:  443,
					Protocol: juneauv1alpha1.TraceProtocolTCP,
				},
			},
		},
	}
}

func TestTraceSessionValidateAccepts(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	if _, err := v.ValidateCreate(context.Background(), validTraceSession()); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

func TestTraceSessionRejectsZeroTraceID(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.TraceID = 0
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error for traceID=0")
	} else if !strings.Contains(err.Error(), "traceID") {
		t.Fatalf("error should mention traceID: %v", err)
	}
}

func TestTraceSessionRejectsPastExpiry(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(-time.Minute))
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error for past expiresAt")
	}
}

func TestTraceSessionRejectsLongExpiry(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(48 * time.Hour))
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error for far-future expiresAt")
	}
}

func TestTraceSessionRejectsTwoSourceSelectors(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.Source.IP = "10.0.1.1"
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error when both pod and ip set")
	}
}

func TestTraceSessionRejectsTCPDestinationWithoutPort(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.Destination.Port = 0
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error for TCP without port")
	}
}

func TestTraceSessionRejectsICMPWithPort(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.Destination.Protocol = juneauv1alpha1.TraceProtocolICMP
	ts.Spec.Destination.Port = 8080
	ts.Spec.InitialTuples[0].Protocol = juneauv1alpha1.TraceProtocolICMP
	ts.Spec.InitialTuples[0].DstPort = 0
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error for ICMP with port")
	}
}

func TestTraceSessionRejectsTupleVPCWithoutVPCID(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.InitialTuples[0].VPCID = 0
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error for VPC scope without vpcID")
	}
}

func TestTraceSessionRejectsBadIPv4(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	ts := validTraceSession()
	ts.Spec.InitialTuples[0].SrcIP = "::1"
	if _, err := v.ValidateCreate(context.Background(), ts); err == nil {
		t.Fatalf("expected error for IPv6 src")
	}
}

func TestTraceSessionImmutableSpec(t *testing.T) {
	v := &TraceSessionCustomValidator{}
	old := validTraceSession()
	updated := old.DeepCopy()
	updated.Spec.Capture.IncludePacketMeta = true
	if _, err := v.ValidateUpdate(context.Background(), old, updated); err == nil {
		t.Fatalf("expected error on spec mutation")
	}
}
