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

	// PodAnnotationNetworks carries a JSON list of the NICs a Pod wants
	// on top of its primary one. See PodNetworkAttachment.
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

	// PodDefaultSubnetName is the Subnet a Pod joins when it names none.
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

// PodNetworkAttachment is one entry of the PodAnnotationNetworks list: a
// NIC the Pod wants in addition to its primary one. The primary NIC is
// described by the single-value annotations instead and can never appear
// here.
type PodNetworkAttachment struct {
	// Interface is the name the NIC gets inside the Pod.
	Interface string `json:"interface"`

	// Subnet is the Subnet the NIC joins. Write either this or
	// L2Network, never both and never neither.
	Subnet string `json:"subnet,omitempty"`

	// L2Network is the L2Network the NIC joins. Write either this or
	// Subnet, never both and never neither.
	//
	// Only an extra NIC may name an L2Network. The primary NIC is
	// configured with the PodAnnotationSubnet annotation, which takes a
	// Subnet name.
	L2Network string `json:"l2Network,omitempty"`

	// Address pins the NIC's address. Left empty the network's pool
	// picks one. An L2Network without a CIDR has no pool and hands out
	// no address at all.
	Address string `json:"address,omitempty"`

	// SecurityGroups lists the SecurityGroups applied to this NIC. All
	// of them must belong to the same Vpc as the network the NIC joins.
	SecurityGroups []string `json:"securityGroups,omitempty"`
}

// PodNetworkAttachments returns every NIC the Pod asks for, the primary
// one first. It fails when the PodAnnotationNetworks annotation cannot be
// read or describes a NIC Juneau cannot build.
func PodNetworkAttachments(annotations map[string]string) ([]PodNetworkAttachment, error) {
	extra, err := ParsePodNetworkAttachments(annotations[PodAnnotationNetworks])
	if err != nil {
		return nil, err
	}
	if errs := ValidatePodNetworkAttachments(podNetworksAnnotationPath(), extra); len(errs) > 0 {
		return nil, errs.ToAggregate()
	}

	out := make([]PodNetworkAttachment, 0, len(extra)+1)
	out = append(out, PodPrimaryNetworkAttachment(annotations))
	return append(out, extra...), nil
}

// PodPrimaryNetworkAttachment describes the NIC every Pod has, read from
// the single-value annotations the Pod controller has always honoured.
func PodPrimaryNetworkAttachment(annotations map[string]string) PodNetworkAttachment {
	subnet := annotations[PodAnnotationSubnet]
	if subnet == "" {
		subnet = PodDefaultSubnetName
	}
	return PodNetworkAttachment{
		Interface:      PodPrimaryInterfaceName,
		Subnet:         subnet,
		Address:        annotations[PodAnnotationAddress],
		SecurityGroups: ParsePodSecurityGroups(annotations[PodAnnotationSecurityGroups]),
	}
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

// ValidatePodNetworkAttachments reports every extra NIC Juneau cannot
// build. Whether the referenced Subnets and SecurityGroups exist is the
// admission webhook's job, because it needs a cluster to look them up in.
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
	if name == PodPrimaryInterfaceName {
		return field.ErrorList{field.Invalid(path, name,
			fmt.Sprintf("%q is the primary NIC; configure it with the %s annotation", PodPrimaryInterfaceName, PodAnnotationSubnet))}
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
	var errs field.ErrorList

	errs = append(errs, validatePodAttachmentNetwork(path, attachment)...)

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

// validatePodAttachmentNetwork enforces that a NIC names exactly one
// network. Naming both a Subnet and an L2Network has no single answer,
// and naming neither leaves Juneau with nothing to attach the NIC to.
func validatePodAttachmentNetwork(path *field.Path, attachment PodNetworkAttachment) field.ErrorList {
	switch {
	case attachment.Subnet == "" && attachment.L2Network == "":
		return field.ErrorList{field.Required(path, "every entry needs a subnet or an l2Network")}
	case attachment.Subnet != "" && attachment.L2Network != "":
		return field.ErrorList{field.Invalid(path.Child("l2Network"), attachment.L2Network,
			"an entry names either a subnet or an l2Network, not both")}
	}

	child, name := "subnet", attachment.Subnet
	if attachment.L2Network != "" {
		child, name = "l2Network", attachment.L2Network
	}
	var errs field.ErrorList
	for _, msg := range validation.IsDNS1123Subdomain(name) {
		errs = append(errs, field.Invalid(path.Child(child), name, msg))
	}
	return errs
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

func podNetworksAnnotationPath() *field.Path {
	return field.NewPath("metadata", "annotations").Key(PodAnnotationNetworks)
}
