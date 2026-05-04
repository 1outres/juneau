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
	"fmt"
	"net/netip"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
var tracesessionlog = logf.Log.WithName("tracesession-resource")

// SetupTraceSessionWebhookWithManager registers the TraceSession
// validating webhook.
func SetupTraceSessionWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.TraceSession{}).
		WithValidator(&TraceSessionCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-tracesession,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=tracesessions,verbs=create;update,versions=v1alpha1,name=vtracesession-v1alpha1.kb.io,admissionReviewVersions=v1

// TraceSessionCustomValidator enforces structural invariants the CRD
// schema cannot express:
//
//   - traceID is non-zero (so kubectl-side default of 0 surfaces as
//     a clear error rather than silently disabling tracing in BPF).
//   - expiresAt lies in the future relative to creationTimestamp /
//     now, and within a sane upper bound (24h) to prevent forgotten
//     sessions consuming dataplane resources indefinitely.
//   - Source and Destination each set exactly one of
//     {podRef, serviceRef, ip}.
//   - Destination protocol/port are consistent (TCP/UDP need port,
//     ICMP must not).
//   - InitialTuples are well-formed: VPC scope requires vpcID,
//     IPs parse as IPv4, ports fit in [0,65535].
//   - Spec is fully immutable on update — TraceSession is ephemeral
//     by design; mutating an in-flight session would corrupt the
//     daemon-side trace state. Rotating a session means deleting
//     and recreating.
//
// +kubebuilder:object:generate=false
type TraceSessionCustomValidator struct{}

var _ webhook.CustomValidator = &TraceSessionCustomValidator{}

// MaxTraceTTL bounds how far in the future spec.expiresAt may be
// set. 24h is generous for a debugging session and far short of
// "forgotten and silently consuming maps for weeks".
const MaxTraceTTL = 24 * time.Hour

// MaxInitialTuples bounds the number of initial tuples a single
// session may carry. The BPF trace_tuple_map is small per session;
// kubectl rarely needs more than one per backend Pod for a Service
// trace. Hard cap rejects pathological inputs at admission.
const MaxInitialTuples = 64

func (v *TraceSessionCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	ts, ok := obj.(*juneauv1alpha1.TraceSession)
	if !ok {
		return nil, fmt.Errorf("expected a TraceSession object but got %T", obj)
	}
	return v.validate(ts, nil)
}

func (v *TraceSessionCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	ts, ok := newObj.(*juneauv1alpha1.TraceSession)
	if !ok {
		return nil, fmt.Errorf("expected a TraceSession object for newObj but got %T", newObj)
	}
	old, ok := oldObj.(*juneauv1alpha1.TraceSession)
	if !ok {
		return nil, fmt.Errorf("expected a TraceSession object for oldObj but got %T", oldObj)
	}
	return v.validate(ts, old)
}

func (v *TraceSessionCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *TraceSessionCustomValidator) validate(ts, old *juneauv1alpha1.TraceSession) (admission.Warnings, error) {
	var errs field.ErrorList

	specPath := field.NewPath("spec")

	if ts.Spec.TraceID == 0 {
		errs = append(errs, field.Invalid(specPath.Child("traceID"), ts.Spec.TraceID, "traceID must be non-zero"))
	}

	switch ts.Spec.Mode {
	case juneauv1alpha1.TraceModeActiveProbe, juneauv1alpha1.TraceModeObserveOnly:
	case "":
		errs = append(errs, field.Required(specPath.Child("mode"), "mode is required"))
	default:
		errs = append(errs, field.NotSupported(specPath.Child("mode"), string(ts.Spec.Mode), []string{
			string(juneauv1alpha1.TraceModeActiveProbe),
			string(juneauv1alpha1.TraceModeObserveOnly),
		}))
	}

	expiryPath := specPath.Child("expiresAt")
	if ts.Spec.ExpiresAt.IsZero() {
		errs = append(errs, field.Required(expiryPath, "expiresAt is required"))
	} else if old == nil {
		// Only enforce the future bound at create time. On update we
		// already require Spec to be unchanged, so a session whose
		// expiresAt was valid at create stays valid as the wall
		// clock advances.
		now := time.Now()
		if !ts.Spec.ExpiresAt.Time.After(now) {
			errs = append(errs, field.Invalid(expiryPath, ts.Spec.ExpiresAt.Time.Format(time.RFC3339),
				"expiresAt must be in the future"))
		}
		if ts.Spec.ExpiresAt.Time.Sub(now) > MaxTraceTTL {
			errs = append(errs, field.Invalid(expiryPath, ts.Spec.ExpiresAt.Time.Format(time.RFC3339),
				fmt.Sprintf("expiresAt may be at most %s in the future", MaxTraceTTL)))
		}
	}

	errs = append(errs, validateTraceCapture(specPath.Child("capture"), &ts.Spec.Capture)...)
	errs = append(errs, validateTraceEndpoint(specPath.Child("source"), &ts.Spec.Source, false)...)
	errs = append(errs, validateTraceEndpoint(specPath.Child("destination"), &ts.Spec.Destination, true)...)

	tuplesPath := specPath.Child("initialTuples")
	if len(ts.Spec.InitialTuples) > MaxInitialTuples {
		errs = append(errs, field.TooMany(tuplesPath, len(ts.Spec.InitialTuples), MaxInitialTuples))
	}
	for i := range ts.Spec.InitialTuples {
		errs = append(errs, validateTraceTuple(tuplesPath.Index(i), &ts.Spec.InitialTuples[i])...)
	}

	if old != nil {
		// Spec is fully immutable. Trace sessions are short-lived and
		// daemons cache spec into BPF maps on first observation —
		// allowing in-place edits would either tear down and re-program
		// (operationally surprising) or split-brain (correctness bug).
		if !traceSessionSpecEqual(&old.Spec, &ts.Spec) {
			errs = append(errs, field.Forbidden(specPath, "spec is immutable; recreate the TraceSession to change it"))
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{
			Group: juneauv1alpha1.GroupVersion.Group,
			Kind:  "TraceSession",
		}, ts.Name, errs)
		tracesessionlog.Info("Validation failed for TraceSession", "name", ts.GetName(), "error", err)
		return nil, err
	}
	return nil, nil
}

func validateTraceCapture(path *field.Path, c *juneauv1alpha1.TraceCaptureConfig) field.ErrorList {
	var errs field.ErrorList
	switch c.Level {
	case "", juneauv1alpha1.TraceCaptureLevelSummary,
		juneauv1alpha1.TraceCaptureLevelDecision,
		juneauv1alpha1.TraceCaptureLevelVerbose:
	default:
		errs = append(errs, field.NotSupported(path.Child("level"), string(c.Level), []string{
			string(juneauv1alpha1.TraceCaptureLevelSummary),
			string(juneauv1alpha1.TraceCaptureLevelDecision),
			string(juneauv1alpha1.TraceCaptureLevelVerbose),
		}))
	}
	return errs
}

func validateTraceEndpoint(path *field.Path, e *juneauv1alpha1.TraceEndpoint, isDestination bool) field.ErrorList {
	var errs field.ErrorList

	set := 0
	if e.PodRef != nil {
		set++
		if e.PodRef.Namespace == "" {
			errs = append(errs, field.Required(path.Child("podRef", "namespace"), "namespace is required"))
		}
		if e.PodRef.Name == "" {
			errs = append(errs, field.Required(path.Child("podRef", "name"), "name is required"))
		}
	}
	if e.ServiceRef != nil {
		set++
		if e.ServiceRef.Namespace == "" {
			errs = append(errs, field.Required(path.Child("serviceRef", "namespace"), "namespace is required"))
		}
		if e.ServiceRef.Name == "" {
			errs = append(errs, field.Required(path.Child("serviceRef", "name"), "name is required"))
		}
	}
	if e.IP != "" {
		set++
		if !isParseableIPv4(e.IP) {
			errs = append(errs, field.Invalid(path.Child("ip"), e.IP, "must be a valid IPv4 address"))
		}
	}
	if set != 1 {
		errs = append(errs, field.Invalid(path, e, "exactly one of podRef, serviceRef, ip must be set"))
	}

	if isDestination {
		switch e.Protocol {
		case juneauv1alpha1.TraceProtocolTCP, juneauv1alpha1.TraceProtocolUDP:
			if e.Port <= 0 {
				errs = append(errs, field.Required(path.Child("port"), "port is required for TCP/UDP destinations"))
			}
		case juneauv1alpha1.TraceProtocolICMP:
			if e.Port != 0 {
				errs = append(errs, field.Invalid(path.Child("port"), e.Port, "port must be empty for ICMP"))
			}
		case "":
			errs = append(errs, field.Required(path.Child("protocol"), "protocol is required on destination"))
		default:
			errs = append(errs, field.NotSupported(path.Child("protocol"), string(e.Protocol), []string{
				string(juneauv1alpha1.TraceProtocolTCP),
				string(juneauv1alpha1.TraceProtocolUDP),
				string(juneauv1alpha1.TraceProtocolICMP),
			}))
		}
		if e.Port < 0 || e.Port > 65535 {
			errs = append(errs, field.Invalid(path.Child("port"), e.Port, "must be in [0,65535]"))
		}
	}

	return errs
}

func validateTraceTuple(path *field.Path, t *juneauv1alpha1.TraceTuple) field.ErrorList {
	var errs field.ErrorList

	switch t.Scope {
	case juneauv1alpha1.TraceTupleScopeHost:
	case juneauv1alpha1.TraceTupleScopeVPC:
		if t.VPCID == 0 {
			errs = append(errs, field.Invalid(path.Child("vpcID"), t.VPCID, "vpcID is required when scope is VPC"))
		}
	case "":
		errs = append(errs, field.Required(path.Child("scope"), "scope is required"))
	default:
		errs = append(errs, field.NotSupported(path.Child("scope"), string(t.Scope), []string{
			string(juneauv1alpha1.TraceTupleScopeHost),
			string(juneauv1alpha1.TraceTupleScopeVPC),
		}))
	}

	if t.SrcIP == "" {
		errs = append(errs, field.Required(path.Child("srcIP"), "srcIP is required"))
	} else if !isParseableIPv4(t.SrcIP) {
		errs = append(errs, field.Invalid(path.Child("srcIP"), t.SrcIP, "must be a valid IPv4 address"))
	}
	if t.DstIP == "" {
		errs = append(errs, field.Required(path.Child("dstIP"), "dstIP is required"))
	} else if !isParseableIPv4(t.DstIP) {
		errs = append(errs, field.Invalid(path.Child("dstIP"), t.DstIP, "must be a valid IPv4 address"))
	}

	if t.SrcPort < 0 || t.SrcPort > 65535 {
		errs = append(errs, field.Invalid(path.Child("srcPort"), t.SrcPort, "must be in [0,65535]"))
	}
	if t.DstPort < 0 || t.DstPort > 65535 {
		errs = append(errs, field.Invalid(path.Child("dstPort"), t.DstPort, "must be in [0,65535]"))
	}

	switch t.Protocol {
	case juneauv1alpha1.TraceProtocolTCP, juneauv1alpha1.TraceProtocolUDP, juneauv1alpha1.TraceProtocolICMP:
	case "":
		errs = append(errs, field.Required(path.Child("protocol"), "protocol is required"))
	default:
		errs = append(errs, field.NotSupported(path.Child("protocol"), string(t.Protocol), []string{
			string(juneauv1alpha1.TraceProtocolTCP),
			string(juneauv1alpha1.TraceProtocolUDP),
			string(juneauv1alpha1.TraceProtocolICMP),
		}))
	}

	return errs
}

func isParseableIPv4(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return addr.Is4()
}

func traceSessionSpecEqual(a, b *juneauv1alpha1.TraceSessionSpec) bool {
	if a.TraceID != b.TraceID || a.Mode != b.Mode {
		return false
	}
	if !a.ExpiresAt.Equal(&b.ExpiresAt) {
		return false
	}
	if a.Capture != b.Capture {
		return false
	}
	if !traceEndpointEqual(&a.Source, &b.Source) || !traceEndpointEqual(&a.Destination, &b.Destination) {
		return false
	}
	if len(a.InitialTuples) != len(b.InitialTuples) {
		return false
	}
	for i := range a.InitialTuples {
		if a.InitialTuples[i] != b.InitialTuples[i] {
			return false
		}
	}
	return true
}

func traceEndpointEqual(a, b *juneauv1alpha1.TraceEndpoint) bool {
	if a.IP != b.IP || a.Protocol != b.Protocol || a.Port != b.Port {
		return false
	}
	if (a.PodRef == nil) != (b.PodRef == nil) {
		return false
	}
	if a.PodRef != nil && *a.PodRef != *b.PodRef {
		return false
	}
	if (a.ServiceRef == nil) != (b.ServiceRef == nil) {
		return false
	}
	if a.ServiceRef != nil && *a.ServiceRef != *b.ServiceRef {
		return false
	}
	return true
}
