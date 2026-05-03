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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

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

// SetupPodWebhookWithManager registers the Pod mutating webhook. The
// webhook injects per-Subnet DNS configuration so cluster-internal
// resolution flows through Juneau's virtual DNS service instead of
// falling back to kube-dns / CoreDNS, which has no knowledge of
// per-VPC isolation.
//
// Validation is intentionally not added here: any Pod we don't
// understand (mirror, hostNetwork, missing subnet, …) is left
// untouched rather than rejected, so a misconfigured webhook can't
// take down the kubelet's Pod admission path.
func SetupPodWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Pod{}).
		WithDefaulter(&PodDNSDefaulter{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate--v1-pod,mutating=true,failurePolicy=ignore,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=mpod-juneau-loutres-me.kb.io,admissionReviewVersions=v1

// PodDNSDefaulter is the CustomDefaulter that rewrites a Pod's
// dnsPolicy / dnsConfig to point at the per-Subnet virtual DNS
// resolver. It runs only on CREATE; once a Pod exists the kubelet
// will never read its dnsConfig again so re-injecting on UPDATE is
// pointless and would surprise users who deliberately changed it.
type PodDNSDefaulter struct {
	client.Client
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
