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
	"net/netip"

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
	"github.com/1outres/juneau/controller/internal/podnetwork"
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

// defaultClusterSearchDomains mirrors the search list kubelet composes
// for ClusterFirst Pods. We assemble it explicitly so dnsPolicy=None Pods
// keep working with relative names like "kubernetes.default" or "demo".
const clusterDomain = "cluster.local"

// nolint:unused
var podlog = logf.Log.WithName("pod-resource")

// SetupPodWebhookWithManager registers the Pod webhooks. Three distinct
// concerns use separate handlers and failure policies:
//
//   - PodDNSDefaulter (mutating): injects per-Subnet DNS config. Failure
//     policy "Ignore" is deliberate — a misconfigured DNS plane should
//     never break Pod admission.
//   - PodSecurityGroupValidator (validating): rejects Pods whose
//     security-groups annotation references missing SGs, references SGs
//     in the wrong Vpc, or violates Vpc.spec.enforceSecurityGroups.
//     Failure policy "Fail" is deliberate — silently admitting a Pod
//     with a non-existent SG would be a real security hole.
//   - PodProbeDefaulter (mutating): routes kubelet network probes through
//     the node-local Juneau probe proxy for overlapping custom VPC
//     addresses. When enabled, it has a separate fail-closed handler scoped
//     to custom Subnet Pods.
//
// All three use the same API reader. Probe rewriting is registered on a
// distinct path; DNS mutation and SecurityGroup validation retain their
// existing controller-runtime registration.
func SetupPodWebhookWithManager(mgr ctrl.Manager, enableProbeRewrite bool, probeProxyPort int32) error {
	if err := ctrl.NewWebhookManagedBy(mgr).For(&corev1.Pod{}).
		WithDefaulter(&PodDNSDefaulter{Reader: mgr.GetAPIReader()}).
		WithValidator(&PodSecurityGroupValidator{Reader: mgr.GetAPIReader()}).
		Complete(); err != nil {
		return err
	}
	if !enableProbeRewrite {
		return nil
	}
	return setupPodProbeWebhookWithManager(mgr, probeProxyPort)
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
	if pod.Annotations[juneauv1alpha1.PodAnnotationDNSInjectSkip] == "true" {
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

	subnetName := juneauv1alpha1.PodPrimaryNetworkAttachment(pod.Annotations).Subnet

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

// PodSecurityGroupValidator enforces the admission rules of every NIC a
// Pod asks for, one NIC at a time:
//
//  1. The NIC lists ≤ juneauv1alpha1.PodSecurityGroupsMax SGs.
//  2. Every named SG exists.
//  3. Every named SG belongs to the same Vpc as the Subnet of that NIC.
//  4. If that Vpc has spec.enforceSecurityGroups=true, the NIC must list
//     at least one valid SG.
//
// It also rejects a juneau.loutres.me/networks annotation Juneau cannot
// turn into NICs, and extra NICs whose Subnet does not exist.
//
// Mirror Pods, hostNetwork Pods, and Pods whose primary Subnet cannot be
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

	nics, errs := podNICsToValidate(pod)
	networks := make(map[string]*podnetwork.Network, len(nics))
	for _, nic := range nics {
		network, nicErrs, err := v.validateNIC(ctx, nic)
		if err != nil {
			return nil, err
		}
		errs = append(errs, nicErrs...)
		if network != nil {
			networks[nic.attachment.Interface] = network
		}
	}
	errs = append(errs, validateNICNetworksDoNotOverlap(nics, networks)...)

	if len(errs) > 0 {
		return nil, apierrors.NewInvalid(schema.GroupKind{Group: "", Kind: "Pod"}, pod.Name, errs)
	}
	return nil, nil
}

// podNIC is one NIC as admission sees it: what the user asked for, where
// to report a problem with it, and whether a network Juneau cannot find
// is fatal.
type podNIC struct {
	attachment juneauv1alpha1.PodNetworkAttachment
	path       *field.Path
	value      any

	// networkRequired tells a NIC whose network is missing apart from
	// one that is merely exempt. The primary NIC is exempt because
	// admission has to keep working while the Juneau control plane is
	// degraded; an extra NIC is not, because a Pod that silently comes up
	// without the NIC it asked for is worse than a Pod that never starts.
	networkRequired bool
}

// podNICsToValidate splits a Pod into the NICs admission has to check.
// Errors come back for entries the annotation itself cannot describe, and
// those NICs are dropped from the returned list.
func podNICsToValidate(pod *corev1.Pod) ([]podNIC, field.ErrorList) {
	annotations := pod.Annotations
	nics := []podNIC{{
		attachment: juneauv1alpha1.PodPrimaryNetworkAttachment(annotations),
		path:       field.NewPath("metadata", "annotations").Key(juneauv1alpha1.PodAnnotationSecurityGroups),
		value:      annotations[juneauv1alpha1.PodAnnotationSecurityGroups],
	}}

	networksPath := field.NewPath("metadata", "annotations").Key(juneauv1alpha1.PodAnnotationNetworks)
	networks := annotations[juneauv1alpha1.PodAnnotationNetworks]
	extra, err := juneauv1alpha1.ParsePodNetworkAttachments(networks)
	if err != nil {
		return nics, field.ErrorList{field.Invalid(networksPath, networks, err.Error())}
	}
	if errs := juneauv1alpha1.ValidatePodNetworkAttachments(networksPath, extra); len(errs) > 0 {
		return nics, errs
	}

	for i, attachment := range extra {
		nics = append(nics, podNIC{
			attachment:      attachment,
			path:            networksPath.Index(i),
			value:           attachment,
			networkRequired: true,
		})
	}
	return nics, nil
}

// validateNIC checks one NIC against the cluster: its SecurityGroups have
// to exist, they have to live in the Vpc of the NIC's own network, and a
// Vpc that enforces SecurityGroups needs at least one on this NIC.
func (v *PodSecurityGroupValidator) validateNIC(ctx context.Context, nic podNIC) (*podnetwork.Network, field.ErrorList, error) {
	if len(nic.attachment.SecurityGroups) > juneauv1alpha1.PodSecurityGroupsMax {
		return nil, field.ErrorList{field.Invalid(nic.path, nic.value,
			fmt.Sprintf("at most %d security groups allowed (got %d)",
				juneauv1alpha1.PodSecurityGroupsMax, len(nic.attachment.SecurityGroups)))}, nil
	}

	ref := podnetwork.AttachmentReference(nic.attachment)
	network, err := podnetwork.Resolve(ctx, v.Reader, ref)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nic.missingReference(fmt.Sprintf("%s does not exist", ref)), nil
		}
		return nil, nil, err
	}

	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: network.Vpc}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return network, nic.missingReference(fmt.Sprintf("Vpc %q of %s does not exist", network.Vpc, ref)), nil
		}
		return nil, nil, err
	}

	var errs field.ErrorList
	var resolved []string
	for i, name := range nic.attachment.SecurityGroups {
		var sg juneauv1alpha1.SecurityGroup
		if err := v.Get(ctx, client.ObjectKey{Name: name}, &sg); err != nil {
			if apierrors.IsNotFound(err) {
				errs = append(errs, field.Invalid(nic.path, nic.value,
					fmt.Sprintf("entry [%d]: SecurityGroup %q does not exist", i, name)))
				continue
			}
			return nil, nil, err
		}
		if sg.Spec.Vpc != vpc.Name {
			errs = append(errs, field.Invalid(nic.path, nic.value,
				fmt.Sprintf("entry [%d]: SecurityGroup %q belongs to Vpc %q (expected %q to match the network of interface %q)",
					i, name, sg.Spec.Vpc, vpc.Name, nic.attachment.Interface)))
			continue
		}
		resolved = append(resolved, name)
	}

	if vpc.Spec.EnforceSecurityGroups && len(resolved) == 0 {
		errs = append(errs, field.Required(nic.path,
			fmt.Sprintf("Vpc %q has enforceSecurityGroups=true; interface %q must reference at least one SecurityGroup",
				vpc.Name, nic.attachment.Interface)))
	}
	return network, errs, nil
}

// validateNICNetworksDoNotOverlap rejects a pod whose NICs would land on
// overlapping prefixes. The pod would get two on-link routes for the same
// addresses and pick one of them at random, which is impossible to debug
// from inside the pod.
//
// A network that hands out no address has no prefix to collide with, so
// an L2Network without a CIDR is left out of the comparison.
func validateNICNetworksDoNotOverlap(nics []podNIC, networks map[string]*podnetwork.Network) field.ErrorList {
	type nicPrefix struct {
		nic     podNIC
		network *podnetwork.Network
		prefix  netip.Prefix
	}

	parsed := make([]nicPrefix, 0, len(nics))
	for _, nic := range nics {
		network, ok := networks[nic.attachment.Interface]
		if !ok || !network.AllocatesAddresses() {
			continue
		}
		prefix, err := netip.ParsePrefix(network.CIDR)
		if err != nil {
			continue
		}
		parsed = append(parsed, nicPrefix{nic: nic, network: network, prefix: prefix.Masked()})
	}

	var errs field.ErrorList
	for i := 1; i < len(parsed); i++ {
		for j := 0; j < i; j++ {
			if !parsed[i].prefix.Overlaps(parsed[j].prefix) {
				continue
			}
			errs = append(errs, field.Invalid(parsed[i].nic.path, parsed[i].nic.value,
				fmt.Sprintf("%s of interface %q and %s of interface %q overlap",
					parsed[i].network.Reference, parsed[i].nic.attachment.Interface,
					parsed[j].network.Reference, parsed[j].nic.attachment.Interface)))
		}
	}
	return errs
}

func (n podNIC) missingReference(detail string) field.ErrorList {
	if !n.networkRequired {
		return nil
	}
	return field.ErrorList{field.Invalid(n.path, n.value, detail)}
}
