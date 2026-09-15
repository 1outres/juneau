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
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	// PodAnnotationSubnet names the Subnet of the Pod's primary NIC.
	PodAnnotationSubnet = "juneau.loutres.me/subnet"

	// PodAnnotationAddress pins the address of the Pod's primary NIC.
	PodAnnotationAddress = "juneau.loutres.me/address"

	// PodAnnotationSecurityGroups carries a comma-separated list of
	// SecurityGroup names for the Pod's primary NIC. The Pod controller
	// transcribes it onto NetworkInterface.spec.securityGroups.
	PodAnnotationSecurityGroups = "juneau.loutres.me/security-groups"

	// PodAnnotationElasticIP names an ElasticIP in the Pod's namespace.
	// The Pod's primary NIC carries the address of that ElasticIP
	// directly, with no NAT in between, and joins no Subnet. It cannot be
	// combined with PodAnnotationSubnet, PodAnnotationAddress or
	// PodAnnotationSecurityGroups.
	PodAnnotationElasticIP = "juneau.loutres.me/elastic-ip"

	// PodAnnotationNetworks carries a JSON list of the NICs a Pod wants.
	// See PodNetworkAttachment.
	PodAnnotationNetworks = "juneau.loutres.me/networks"

	// PodAnnotationDNSInjectSkip lets users opt a single Pod out of DNS
	// injection (for debugging or for hostNetwork-equivalent workloads
	// that manage resolv.conf themselves). Value is expected to be the
	// literal string "true".
	PodAnnotationDNSInjectSkip = "juneau.loutres.me/dns-inject-skip"
)

const (
	// PodPrimaryInterfaceName is the NIC every Pod gets. The container
	// runtime demands a CNI interface under this exact name carrying at
	// least one IP, so the primary NIC can neither be renamed nor be
	// address-less. Probes, DNS and Service backends all follow it.
	PodPrimaryInterfaceName = "eth0"

	// PodDefaultSubnetName is the Subnet the primary NIC joins when no
	// annotation describes that NIC.
	PodDefaultSubnetName = "default"

	// PodSecurityGroupsMax matches NetworkInterface.spec.securityGroups
	// MaxItems and the BPF MAX_SGS_PER_NIC ceiling. Exceeding it is a
	// hard reject at admission so we never silently truncate.
	PodSecurityGroupsMax = 2

	// PodInterfaceNameMaxLen is the longest interface name a NIC may
	// carry. Linux itself takes 15 characters, but Juneau names the host
	// side of the veth "<interface>+<container id>" and that name has to
	// fit in the same 15 characters with enough of the container id left
	// to tell two sandboxes of the same NIC apart.
	PodInterfaceNameMaxLen = 8
)

// PodNetworkAttachment is one NIC a Pod asks for, in the shape of one
// entry of the PodAnnotationNetworks list. The primary NIC may be one of
// the entries too. When no entry names it, the single-value annotations
// describe it instead.
type PodNetworkAttachment struct {
	// Interface is the name the NIC gets inside the Pod.
	Interface string `json:"interface"`

	// Subnet is the Subnet the NIC joins. Write exactly one of Subnet,
	// L2Network and ElasticIP.
	Subnet string `json:"subnet,omitempty"`

	// L2Network is the L2Network the NIC joins. Write exactly one of
	// Subnet, L2Network and ElasticIP.
	//
	// The primary NIC may join an L2Network only when the L2Network has
	// both spec.cidr and spec.gateway: the container runtime needs an
	// address on the primary NIC, and the Pod needs a gateway for its
	// default route.
	L2Network string `json:"l2Network,omitempty"`

	// ElasticIP names an ElasticIP in the Pod's namespace. The NIC
	// carries the address of that ElasticIP directly and joins no Vpc.
	// Write exactly one of Subnet, L2Network and ElasticIP.
	//
	// Such a NIC takes no Address, because the ElasticIP already owns
	// the address, and no SecurityGroups, because it belongs to no Vpc.
	// One ElasticIP can sit on only one NIC of a Pod.
	ElasticIP string `json:"elasticIP,omitempty"`

	// Address pins the NIC's address. Left empty the network's pool
	// picks one. An L2Network without a CIDR has no pool and hands out
	// no address at all.
	Address string `json:"address,omitempty"`

	// SecurityGroups lists the SecurityGroups applied to this NIC. All
	// of them must belong to the same Vpc as the network the NIC joins.
	SecurityGroups []string `json:"securityGroups,omitempty"`
}

// PodNetworkAttachmentSource points at the annotation that describes a
// NIC, so a problem with the NIC can be reported where the user wrote it.
type PodNetworkAttachmentSource struct {
	// Annotation is PodAnnotationNetworks for an entry of that list. A
	// primary NIC the single-value annotations describe has
	// PodAnnotationElasticIP when that annotation is set, and
	// PodAnnotationSubnet otherwise, also when the NIC falls back to the
	// default Subnet.
	Annotation string

	// Index is the position of the entry in the PodAnnotationNetworks
	// list. It is zero for every other annotation.
	Index int
}

// Path is the field path of the annotation the source points at, or of
// the list entry when the annotation is PodAnnotationNetworks.
func (s PodNetworkAttachmentSource) Path() *field.Path {
	path := podAnnotationPath(s.Annotation)
	if s.Annotation == PodAnnotationNetworks {
		return path.Index(s.Index)
	}
	return path
}

// ResolvedPodNetworkAttachment is a NIC a Pod asks for, together with
// the annotation that describes it.
type ResolvedPodNetworkAttachment struct {
	PodNetworkAttachment

	Source PodNetworkAttachmentSource
}

// PodNetworkAttachments returns every NIC the Pod asks for, the primary
// one first. It fails when the annotations cannot be read or describe
// NICs Juneau cannot build; ResolvePodNetworkAttachments lists the rules.
func PodNetworkAttachments(annotations map[string]string) ([]PodNetworkAttachment, error) {
	resolved, errs := ResolvePodNetworkAttachments(annotations)
	if len(errs) > 0 {
		return nil, errs.ToAggregate()
	}

	out := make([]PodNetworkAttachment, 0, len(resolved))
	for _, nic := range resolved {
		out = append(out, nic.PodNetworkAttachment)
	}
	return out, nil
}

// PodPrimaryNetworkAttachment returns the NIC every Pod has. It fails in
// the same cases as PodNetworkAttachments, because a networks entry can
// describe the primary NIC too.
func PodPrimaryNetworkAttachment(annotations map[string]string) (PodNetworkAttachment, error) {
	attachments, err := PodNetworkAttachments(annotations)
	if err != nil {
		return PodNetworkAttachment{}, err
	}
	return attachments[0], nil
}

// ResolvePodNetworkAttachments reads every NIC the Pod asks for, the
// primary one first, and tells which annotation describes each of them.
//
// The primary NIC is described in exactly one of these ways:
//
//   - The PodAnnotationNetworks entry whose interface is
//     PodPrimaryInterfaceName. None of PodAnnotationSubnet,
//     PodAnnotationAddress, PodAnnotationSecurityGroups and
//     PodAnnotationElasticIP may be set next to it.
//   - PodAnnotationElasticIP. None of PodAnnotationSubnet,
//     PodAnnotationAddress and PodAnnotationSecurityGroups may be set
//     next to it.
//   - PodAnnotationSubnet with PodAnnotationAddress and
//     PodAnnotationSecurityGroups. An empty or missing
//     PodAnnotationSubnet means PodDefaultSubnetName.
//
// In the first two cases an annotation that may not be set counts as set
// as soon as its key is present, even with an empty value, so a leftover
// key is reported instead of being ignored.
//
// Every problem comes back, each at the annotation it belongs to. Whether
// the named objects exist is the admission webhook's job, because it
// needs a cluster to look them up in.
func ResolvePodNetworkAttachments(annotations map[string]string) ([]ResolvedPodNetworkAttachment, field.ErrorList) {
	networksPath := podAnnotationPath(PodAnnotationNetworks)
	entries, err := ParsePodNetworkAttachments(annotations[PodAnnotationNetworks])
	if err != nil {
		return nil, field.ErrorList{field.Invalid(networksPath, annotations[PodAnnotationNetworks], err.Error())}
	}

	errs := ValidatePodNetworkAttachments(networksPath, entries)
	primaryEntry := slices.IndexFunc(entries, func(entry PodNetworkAttachment) bool {
		return entry.Interface == PodPrimaryInterfaceName
	})
	describedByEntry := primaryEntry >= 0
	if describedByEntry {
		errs = append(errs, forbidPodAnnotations(annotations,
			describedElsewhere(PodAnnotationNetworks),
			PodAnnotationSubnet, PodAnnotationAddress, PodAnnotationSecurityGroups, PodAnnotationElasticIP)...)
	} else {
		errs = append(errs, validatePodElasticIPAnnotation(annotations)...)
	}
	if len(errs) > 0 {
		return nil, errs
	}

	resolved := make([]ResolvedPodNetworkAttachment, 0, len(entries)+1)
	if describedByEntry {
		resolved = append(resolved, resolvedPodNetworksEntry(entries, primaryEntry))
	} else {
		resolved = append(resolved, resolvedPodPrimaryAnnotations(annotations))
	}
	for i := range entries {
		if i != primaryEntry {
			resolved = append(resolved, resolvedPodNetworksEntry(entries, i))
		}
	}

	if errs := validatePodElasticIPsNotShared(resolved); len(errs) > 0 {
		return nil, errs
	}
	return resolved, nil
}

// ParsePodNetworkAttachments decodes the PodAnnotationNetworks value.
// Unknown fields are rejected rather than dropped, so a misspelled key is
// reported instead of silently giving the Pod a NIC nobody asked for.
func ParsePodNetworkAttachments(annotation string) ([]PodNetworkAttachment, error) {
	if strings.TrimSpace(annotation) == "" {
		return nil, nil
	}

	decoder := json.NewDecoder(strings.NewReader(annotation))
	decoder.DisallowUnknownFields()

	var attachments []PodNetworkAttachment
	if err := decoder.Decode(&attachments); err != nil {
		return nil, fmt.Errorf("read the %s annotation: %w", PodAnnotationNetworks, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("read the %s annotation: unexpected content after the list", PodAnnotationNetworks)
	}
	return attachments, nil
}

// ValidatePodNetworkAttachments reports every entry of the
// PodAnnotationNetworks list Juneau cannot build on its own. The rules
// that tie an entry to the other annotations are checked by
// ResolvePodNetworkAttachments.
func ValidatePodNetworkAttachments(path *field.Path, attachments []PodNetworkAttachment) field.ErrorList {
	var errs field.ErrorList
	seen := make(map[string]struct{}, len(attachments))
	for i := range attachments {
		entry := path.Index(i)
		name := attachments[i].Interface
		errs = append(errs, validatePodInterfaceName(entry.Child("interface"), name)...)
		if _, duplicate := seen[name]; duplicate {
			errs = append(errs, field.Duplicate(entry.Child("interface"), name))
		}
		seen[name] = struct{}{}
		errs = append(errs, validatePodAttachmentTarget(entry, attachments[i])...)
	}
	return errs
}

func validatePodInterfaceName(path *field.Path, name string) field.ErrorList {
	if name == "" {
		return field.ErrorList{field.Required(path, "every entry needs an interface name")}
	}
	if len(name) > PodInterfaceNameMaxLen {
		return field.ErrorList{field.Invalid(path, name,
			fmt.Sprintf("an interface name may hold at most %d characters", PodInterfaceNameMaxLen))}
	}
	var errs field.ErrorList
	for _, msg := range validation.IsDNS1123Label(name) {
		errs = append(errs, field.Invalid(path, name, msg))
	}
	return errs
}

func validatePodAttachmentTarget(path *field.Path, attachment PodNetworkAttachment) field.ErrorList {
	errs := validatePodAttachmentNetwork(path, attachment)
	if attachment.ElasticIP != "" {
		return append(errs, validatePodElasticIPAttachmentFields(path, attachment)...)
	}

	if attachment.Address != "" && net.ParseIP(attachment.Address) == nil {
		errs = append(errs, field.Invalid(path.Child("address"), attachment.Address, "address must be an IP address"))
	}

	sgPath := path.Child("securityGroups")
	if len(attachment.SecurityGroups) > PodSecurityGroupsMax {
		errs = append(errs, field.Invalid(sgPath, attachment.SecurityGroups,
			fmt.Sprintf("at most %d security groups allowed (got %d)", PodSecurityGroupsMax, len(attachment.SecurityGroups))))
	}
	seen := make(map[string]struct{}, len(attachment.SecurityGroups))
	for i, name := range attachment.SecurityGroups {
		if name == "" {
			errs = append(errs, field.Required(sgPath.Index(i), "a security group name cannot be empty"))
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			errs = append(errs, field.Duplicate(sgPath.Index(i), name))
		}
		seen[name] = struct{}{}
	}
	return errs
}

// validatePodElasticIPAttachmentFields rejects the fields an entry on an
// ElasticIP cannot use. Silently dropping them would leave the user
// believing the NIC has a pinned address or is filtered.
func validatePodElasticIPAttachmentFields(path *field.Path, attachment PodNetworkAttachment) field.ErrorList {
	var errs field.ErrorList
	if attachment.Address != "" {
		errs = append(errs, field.Forbidden(path.Child("address"),
			"a NIC on an elasticIP carries the address of that ElasticIP and cannot pin another one"))
	}
	if len(attachment.SecurityGroups) > 0 {
		errs = append(errs, field.Forbidden(path.Child("securityGroups"),
			"a NIC on an elasticIP belongs to no Vpc and takes no SecurityGroups"))
	}
	return errs
}

// podAttachmentNetwork is one of the fields an entry can name its
// network with.
type podAttachmentNetwork struct {
	child string
	name  string
}

// validatePodAttachmentNetwork enforces that a NIC names exactly one
// network. Naming more than one has no single answer, and naming none
// leaves Juneau with nothing to attach the NIC to.
func validatePodAttachmentNetwork(path *field.Path, attachment PodNetworkAttachment) field.ErrorList {
	named := slices.DeleteFunc([]podAttachmentNetwork{
		{child: "subnet", name: attachment.Subnet},
		{child: "l2Network", name: attachment.L2Network},
		{child: "elasticIP", name: attachment.ElasticIP},
	}, func(network podAttachmentNetwork) bool {
		return network.name == ""
	})

	switch len(named) {
	case 0:
		return field.ErrorList{field.Required(path, "every entry needs a subnet, an l2Network or an elasticIP")}
	case 1:
	default:
		return field.ErrorList{field.Invalid(path.Child(named[1].child), named[1].name,
			"an entry names exactly one of subnet, l2Network and elasticIP")}
	}

	var errs field.ErrorList
	for _, msg := range validation.IsDNS1123Subdomain(named[0].name) {
		errs = append(errs, field.Invalid(path.Child(named[0].child), named[0].name, msg))
	}
	return errs
}

// validatePodElasticIPAnnotation checks PodAnnotationElasticIP when it
// describes the primary NIC.
func validatePodElasticIPAnnotation(annotations map[string]string) field.ErrorList {
	name, set := annotations[PodAnnotationElasticIP]
	if !set {
		return nil
	}

	path := podAnnotationPath(PodAnnotationElasticIP)
	var errs field.ErrorList
	if name == "" {
		errs = append(errs, field.Required(path, "name an ElasticIP in the namespace of the Pod"))
	} else {
		for _, msg := range validation.IsDNS1123Subdomain(name) {
			errs = append(errs, field.Invalid(path, name, msg))
		}
	}
	return append(errs, forbidPodAnnotations(annotations,
		describedElsewhere(PodAnnotationElasticIP),
		PodAnnotationSubnet, PodAnnotationAddress, PodAnnotationSecurityGroups)...)
}

// validatePodElasticIPsNotShared rejects one ElasticIP on two NICs of the
// Pod. An ElasticIP holds a single address, and one address cannot sit on
// two NICs.
func validatePodElasticIPsNotShared(resolved []ResolvedPodNetworkAttachment) field.ErrorList {
	var errs field.ErrorList
	seen := make(map[string]struct{}, len(resolved))
	for _, nic := range resolved {
		name := nic.ElasticIP
		if name == "" {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			path := nic.Source.Path()
			if nic.Source.Annotation == PodAnnotationNetworks {
				path = path.Child("elasticIP")
			}
			errs = append(errs, field.Duplicate(path, name))
			continue
		}
		seen[name] = struct{}{}
	}
	return errs
}

// forbidPodAnnotations reports every key in keys that is set on the Pod.
func forbidPodAnnotations(annotations map[string]string, detail string, keys ...string) field.ErrorList {
	var errs field.ErrorList
	for _, key := range keys {
		if _, set := annotations[key]; set {
			errs = append(errs, field.Forbidden(podAnnotationPath(key), detail))
		}
	}
	return errs
}

func describedElsewhere(annotation string) string {
	return fmt.Sprintf("the %s annotation already describes interface %q; remove this annotation", annotation, PodPrimaryInterfaceName)
}

func resolvedPodNetworksEntry(entries []PodNetworkAttachment, index int) ResolvedPodNetworkAttachment {
	return ResolvedPodNetworkAttachment{
		PodNetworkAttachment: entries[index],
		Source:               PodNetworkAttachmentSource{Annotation: PodAnnotationNetworks, Index: index},
	}
}

// resolvedPodPrimaryAnnotations reads the primary NIC from the
// single-value annotations. They are already validated.
func resolvedPodPrimaryAnnotations(annotations map[string]string) ResolvedPodNetworkAttachment {
	if name, set := annotations[PodAnnotationElasticIP]; set {
		return ResolvedPodNetworkAttachment{
			PodNetworkAttachment: PodNetworkAttachment{Interface: PodPrimaryInterfaceName, ElasticIP: name},
			Source:               PodNetworkAttachmentSource{Annotation: PodAnnotationElasticIP},
		}
	}

	subnet := annotations[PodAnnotationSubnet]
	if subnet == "" {
		subnet = PodDefaultSubnetName
	}
	return ResolvedPodNetworkAttachment{
		PodNetworkAttachment: PodNetworkAttachment{
			Interface:      PodPrimaryInterfaceName,
			Subnet:         subnet,
			Address:        annotations[PodAnnotationAddress],
			SecurityGroups: ParsePodSecurityGroups(annotations[PodAnnotationSecurityGroups]),
		},
		Source: PodNetworkAttachmentSource{Annotation: PodAnnotationSubnet},
	}
}

// ParsePodSecurityGroups parses the comma-separated value of the
// PodAnnotationSecurityGroups annotation into a deduplicated, sorted
// slice. Empty / whitespace-only entries are dropped.
//
// Sorting yields a stable spec.securityGroups regardless of how the user
// wrote the annotation, which keeps NetworkInterface diffs minimal.
func ParsePodSecurityGroups(annotation string) []string {
	if strings.TrimSpace(annotation) == "" {
		return nil
	}
	parts := strings.Split(annotation, ",")
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

func podAnnotationPath(key string) *field.Path {
	return field.NewPath("metadata", "annotations").Key(key)
}
