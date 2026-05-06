/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1alpha1

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// defaultVpcName names the implicit Vpc that holds Pods which do not
// participate in any custom-VPC isolation. We deliberately leave its
// Pods on kube-dns: the only functional value Juneau DNS provides is
// VPC-scoped resolution (cross-VPC NXDOMAIN, shared-service routing,
// per-Subnet upstream forwarding), none of which is meaningful inside
// the default Vpc, and overriding kube-dns there would extend the
// blast radius of any DNS-plane bug to the cluster's hot path.
//
// Kept as a private const to avoid coupling this package to svcpolicy
// from the daemon module — the value is fixed by Vpc bootstrapping.
const defaultVpcName = "default"

const (
	// PodAnnotationSubnet matches the per-Pod subnet selector used by
	// pod_controller — kept in sync rather than re-imported so this
	// webhook stays a thin transformation layer.
	PodAnnotationSubnet = "juneau.loutres.me/subnet"

	// PodAnnotationDNSInjectSkip lets users opt a single Pod out of
	// DNS injection (for debugging or for hostNetwork-equivalent
	// workloads that manage resolv.conf themselves). Value is
	// expected to be the literal string "true".
	PodAnnotationDNSInjectSkip = "juneau.loutres.me/dns-inject-skip"

	// PodAnnotationSecurityGroups carries a comma-separated list of
	// SecurityGroup names that should be attached to the Pod's
	// NetworkInterface. The Pod controller transcribes this onto
	// NetworkInterface.spec.securityGroups; this webhook validates it.
	PodAnnotationSecurityGroups = "juneau.loutres.me/security-groups"

	// PodSecurityGroupsMax matches NetworkInterface.spec.securityGroups
	// MaxItems and the BPF MAX_SGS_PER_NIC ceiling. Exceeding this is a
	// hard reject at admission so we never silently truncate.
	PodSecurityGroupsMax = 2

	// defaultClusterSearchDomains mirrors the search list kubelet
	// composes for ClusterFirst Pods. We assemble it explicitly so
	// dnsPolicy=None Pods keep working with relative names like
	// "kubernetes.default" or "demo".
	clusterDomain = "cluster.local"

	// dnsPodSubnetDefault is the implicit subnet a Pod with no
	// PodAnnotationSubnet falls into — same default the Pod controller
	// uses to provision NetworkInterface.
	dnsPodSubnetDefault = "default"
)

// nolint:unused
var podlog = logf.Log.WithName("pod-resource")

// SetupPodWebhookWithManager registers the Pod webhook. Two distinct
// concerns are layered behind a single webhook registration:
//
//   - PodDNSDefaulter (mutating): injects per-Subnet DNS config. Failure
//     policy "Ignore" is deliberate — a misconfigured DNS plane should
//     never break Pod admission.
//   - PodSecurityGroupValidator (validating): rejects Pods whose
//     security-groups annotation references missing SGs, references SGs
//     in the wrong Vpc, or violates Vpc.spec.enforceSecurityGroups.
//     Failure policy "Fail" is deliberate — silently admitting a Pod
//     with a non-existent SG would be a real security hole.
//
// Both pieces share the same client; controller-runtime treats them as
// separate webhook handlers under the same registration.
func SetupPodWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Pod{}).
		WithDefaulter(&PodDNSDefaulter{Reader: mgr.GetAPIReader()}).
		WithValidator(&PodSecurityGroupValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate--v1-pod,mutating=true,failurePolicy=ignore,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=mpod-juneau-loutres-me.kb.io,admissionReviewVersions=v1

// PodDNSDefaulter is the CustomDefaulter that rewrites a Pod's
// dnsPolicy / dnsConfig to point at the per-Subnet virtual DNS
// resolver. It runs only on CREATE; once a Pod exists the kubelet
// will never read its dnsConfig again so re-injecting on UPDATE is
// pointless and would surprise users who deliberately changed it.
type PodDNSDefaulter struct {
	client.Reader
}

var _ webhook.CustomDefaulter = &PodDNSDefaulter{}

// Default mutates the Pod object in place. Any condition that prevents
// safe mutation (mirror Pod, hostNetwork, unresolvable Subnet, missing
// DNS VIP, explicit user opt-out, user already chose dnsPolicy=None)
// is treated as a no-op rather than an error so admission keeps
// succeeding even when Juneau's DNS plane is degraded.
func (d *PodDNSDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return fmt.Errorf("expected a Pod object but got %T", obj)
	}

	if pod.Spec.HostNetwork {
		return nil
	}
	if pod.Annotations[PodAnnotationDNSInjectSkip] == "true" {
		return nil
	}
	if _, isMirror := pod.Annotations["kubernetes.io/config.mirror"]; isMirror {
		return nil
	}
	// User explicitly chose a non-cluster DNS policy; don't override.
	switch pod.Spec.DNSPolicy {
	case "", corev1.DNSClusterFirst, corev1.DNSClusterFirstWithHostNet:
		// fall through — eligible for injection
	default:
		return nil
	}

	subnetName := pod.Annotations[PodAnnotationSubnet]
	if subnetName == "" {
		subnetName = dnsPodSubnetDefault
	}

	var subnet juneauv1alpha1.Subnet
	if err := d.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
		if apierrors.IsNotFound(err) {
			// Subnet referenced by annotation isn't there yet; leave
			// the Pod alone. The Pod controller will surface a
			// scheduling error if the subnet is genuinely missing.
			return nil
		}
		return fmt.Errorf("get subnet %q: %w", subnetName, err)
	}

	// Pods whose Subnet belongs to the default Vpc keep talking to
	// kube-dns — see the comment on defaultVpcName for the rationale.
	// We compare on Subnet.Spec.Vpc (not the Pod annotation) so the
	// rule is independent of how the Pod was authored.
	if subnet.Spec.Vpc == defaultVpcName {
		return nil
	}

	if subnet.Status.DNS == "" {
		// Subnet is not (yet) advertising a DNS VIP — its prefix may
		// be too narrow (/31, /32) or the controller has not
		// reconciled it yet. Either way leave the Pod with whatever
		// dnsPolicy it had so it can fall back to kube-dns if
		// configured.
		return nil
	}

	pod.Spec.DNSPolicy = corev1.DNSNone
	pod.Spec.DNSConfig = mergeDNSConfig(pod.Spec.DNSConfig, subnet.Status.DNS, pod.Namespace)
	return nil
}

// mergeDNSConfig returns a *corev1.PodDNSConfig that points at the
// supplied DNS VIP, preserving any user-supplied entries. The merge
// rules are intentionally simple:
//
//   - Nameservers: VIP is prepended; duplicate Nameservers from the
//     existing config are dropped. We cap the result at 3 entries
//     (the kubelet enforces this; exceeding it would make Pod
//     creation fail on validation).
//   - Searches: replaced with the standard cluster set if the user
//     supplied none, otherwise left untouched (the user knows what
//     they need).
//   - Options: ndots=5 added if no ndots option already exists,
//     matching kubelet's ClusterFirst defaults.
func mergeDNSConfig(existing *corev1.PodDNSConfig, dnsVIP, podNamespace string) *corev1.PodDNSConfig {
	out := corev1.PodDNSConfig{}
	if existing != nil {
		out = *existing.DeepCopy()
	}

	servers := []string{dnsVIP}
	for _, s := range out.Nameservers {
		if s == dnsVIP {
			continue
		}
		servers = append(servers, s)
	}
	if len(servers) > 3 {
		servers = servers[:3]
	}
	out.Nameservers = servers

	if len(out.Searches) == 0 {
		out.Searches = []string{
			fmt.Sprintf("%s.svc.%s", podNamespace, clusterDomain),
			fmt.Sprintf("svc.%s", clusterDomain),
			clusterDomain,
		}
	}

	hasNdots := false
	for _, opt := range out.Options {
		if opt.Name == "ndots" {
			hasNdots = true
			break
		}
	}
	if !hasNdots {
		ndots := "5"
		out.Options = append(out.Options, corev1.PodDNSConfigOption{
			Name:  "ndots",
			Value: &ndots,
		})
	}

	return &out
}

// +kubebuilder:webhook:path=/validate--v1-pod,mutating=false,failurePolicy=ignore,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=vpod-juneau-loutres-me.kb.io,admissionReviewVersions=v1

// PodSecurityGroupValidator enforces SG-related admission rules:
//
//  1. The juneau.loutres.me/security-groups annotation, when present,
//     parses into ≤ PodSecurityGroupsMax names.
//  2. Every named SG exists.
//  3. Every named SG belongs to the same Vpc as the Pod's Subnet.
//  4. If the owning Vpc has spec.enforceSecurityGroups=true, the Pod
//     must list at least one valid SG.
//
// Mirror Pods, hostNetwork Pods, and Pods whose Subnet cannot be
// resolved are always exempt — admission must keep working when the
// Juneau control plane is degraded.
//
// +kubebuilder:object:generate=false
type PodSecurityGroupValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &PodSecurityGroupValidator{}

func (v *PodSecurityGroupValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object but got %T", obj)
	}
	return v.validate(ctx, pod)
}

func (v *PodSecurityGroupValidator) ValidateUpdate(ctx context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	pod, ok := newObj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object for newObj but got %T", newObj)
	}
	return v.validate(ctx, pod)
}

func (v *PodSecurityGroupValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *PodSecurityGroupValidator) validate(ctx context.Context, pod *corev1.Pod) (admission.Warnings, error) {
	if pod.Spec.HostNetwork {
		return nil, nil
	}
	if _, isMirror := pod.Annotations["kubernetes.io/config.mirror"]; isMirror {
		return nil, nil
	}

	annotation := pod.Annotations[PodAnnotationSecurityGroups]
	names := parsePodSGAnnotation(annotation)

	annPath := field.NewPath("metadata", "annotations").Key(PodAnnotationSecurityGroups)
	var errs field.ErrorList

	if len(names) > PodSecurityGroupsMax {
		errs = append(errs, field.Invalid(annPath, annotation,
			fmt.Sprintf("at most %d security groups allowed (got %d)", PodSecurityGroupsMax, len(names))))
	}

	subnetName := pod.Annotations[PodAnnotationSubnet]
	if subnetName == "" {
		subnetName = dnsPodSubnetDefault
	}

	var subnet juneauv1alpha1.Subnet
	if err := v.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
		if apierrors.IsNotFound(err) {
			// Subnet missing → Pod controller will surface a scheduling
			// error; do not double-reject here.
			return nil, nil
		}
		return nil, err
	}

	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	resolvedNames := names
	if len(errs) == 0 {
		resolvedNames = nil
		for i, name := range names {
			var sg juneauv1alpha1.SecurityGroup
			if err := v.Get(ctx, client.ObjectKey{Name: name}, &sg); err != nil {
				if apierrors.IsNotFound(err) {
					errs = append(errs, field.Invalid(annPath, annotation,
						fmt.Sprintf("entry [%d]: SecurityGroup %q does not exist", i, name)))
					continue
				}
				return nil, err
			}
			if sg.Spec.Vpc != vpc.Name {
				errs = append(errs, field.Invalid(annPath, annotation,
					fmt.Sprintf("entry [%d]: SecurityGroup %q belongs to Vpc %q (expected %q to match the Pod's Subnet)", i, name, sg.Spec.Vpc, vpc.Name)))
				continue
			}
			resolvedNames = append(resolvedNames, name)
		}
	}

	if vpc.Spec.EnforceSecurityGroups && len(resolvedNames) == 0 {
		errs = append(errs, field.Required(annPath,
			fmt.Sprintf("Vpc %q has enforceSecurityGroups=true; the Pod must reference at least one SecurityGroup", vpc.Name)))
	}

	if len(errs) > 0 {
		return nil, apierrors.NewInvalid(schema.GroupKind{Group: "", Kind: "Pod"}, pod.Name, errs)
	}

	return nil, nil
}

// parsePodSGAnnotation parses a comma-separated list, trimming and
// deduplicating. Returns nil for empty input.
func parsePodSGAnnotation(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
