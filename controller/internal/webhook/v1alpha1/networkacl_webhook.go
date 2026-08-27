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

	"k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
var networkacllog = logf.Log.WithName("networkacl-resource")

// SetupNetworkACLWebhookWithManager registers the NetworkACL validating
// webhook.
func SetupNetworkACLWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.NetworkACL{}).
		WithValidator(&NetworkACLCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-networkacl,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkacls,verbs=create;update;delete,versions=v1alpha1,name=vnetworkacl-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkACLCustomValidator enforces structural invariants the CRD
// schema cannot express:
//
//   - Vpc reference exists and is immutable.
//   - Each rule's CIDR parses as an IPv4 prefix.
//   - Each rule's port range has from <= to.
//   - Each rule's protocol resolves to an IP protocol number, and ports
//     are set only on protocols that carry them (tcp and udp).
//   - Priorities are unique within each direction (so the priority
//     order is total).
//   - Each direction fits NetworkACLMaxEntriesPerDirection expanded
//     entries, so the data plane never has to refuse a direction.
//   - At delete time, no Subnet still references this ACL.
//
// +kubebuilder:object:generate=false
type NetworkACLCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &NetworkACLCustomValidator{}

func (v *NetworkACLCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	acl, ok := obj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkACL object but got %T", obj)
	}
	return v.validate(ctx, acl, nil)
}

func (v *NetworkACLCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	acl, ok := newObj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkACL object for newObj but got %T", newObj)
	}
	old, ok := oldObj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkACL object for oldObj but got %T", oldObj)
	}
	return v.validate(ctx, acl, old)
}

func (v *NetworkACLCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	acl, ok := obj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkACL object but got %T", obj)
	}

	// Refuse delete while any Subnet still references the ACL so users
	// do not silently lose their attachment via dangling-reference
	// pruning at reconcile time. (Mirrors the SecurityGroup webhook.)
	var subnets juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnets); err != nil {
		return nil, err
	}
	for i := range subnets.Items {
		s := &subnets.Items[i]
		if s.Spec.NetworkACL == acl.Name {
			return nil, errors.NewForbidden(
				schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "networkacls"},
				acl.Name,
				fmt.Errorf("NetworkACL is referenced by Subnet %q", s.Name),
			)
		}
	}

	return nil, nil
}

func (v *NetworkACLCustomValidator) validate(ctx context.Context, acl, old *juneauv1alpha1.NetworkACL) (admission.Warnings, error) {
	var errs field.ErrorList

	vpcPath := field.NewPath("spec", "vpc")
	if len(apivalidation.NameIsDNSSubdomain(acl.Spec.Vpc, false)) > 0 {
		errs = append(errs, field.Invalid(vpcPath, acl.Spec.Vpc, "must be a valid DNS subdomain"))
	} else if shouldCheckReferences(acl) {
		var vpc juneauv1alpha1.Vpc
		if err := v.Get(ctx, client.ObjectKey{Name: acl.Spec.Vpc}, &vpc); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(vpcPath, acl.Spec.Vpc, "referenced Vpc does not exist"))
			} else {
				return nil, err
			}
		}
	}

	if old != nil && acl.Spec.Vpc != old.Spec.Vpc {
		errs = append(errs, field.Invalid(vpcPath, acl.Spec.Vpc, "vpc is immutable"))
	}

	if acl.Spec.Ingress != nil {
		errs = append(errs, validateNetworkACLDirection(field.NewPath("spec", "ingress"), *acl.Spec.Ingress)...)
	}
	if acl.Spec.Egress != nil {
		errs = append(errs, validateNetworkACLDirection(field.NewPath("spec", "egress"), *acl.Spec.Egress)...)
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkACL"}, acl.Name, errs)
		networkacllog.Info("Validation failed for NetworkACL", "name", acl.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func validateNetworkACLDirection(path *field.Path, rules []juneauv1alpha1.NetworkACLRule) field.ErrorList {
	var errs field.ErrorList
	seenPriorities := make(map[int32]int, len(rules))

	for i, rule := range rules {
		errs = append(errs, validateNetworkACLRule(path.Index(i), rule)...)

		if prev, ok := seenPriorities[rule.Priority]; ok {
			errs = append(errs, field.Invalid(path.Index(i).Child("priority"), rule.Priority,
				fmt.Sprintf("duplicates priority of rule [%d]; priorities must be unique within a direction", prev)))
			continue
		}
		seenPriorities[rule.Priority] = i
	}

	errs = append(errs, validateNetworkACLDirectionCapacity(path, rules)...)
	return errs
}

// validateNetworkACLDirectionCapacity rejects a direction that does not
// fit its data plane budget. Accepting it would leave the ACL degraded
// after admission with one direction refused by the daemon, so the
// answer belongs here rather than in status.
func validateNetworkACLDirectionCapacity(path *field.Path, rules []juneauv1alpha1.NetworkACLRule) field.ErrorList {
	entries := juneauv1alpha1.NetworkACLDirectionEntryCount(rules)
	if entries <= juneauv1alpha1.NetworkACLMaxEntriesPerDirection {
		return nil
	}
	err := field.TooMany(path, entries, juneauv1alpha1.NetworkACLMaxEntriesPerDirection)
	// field.TooMany counts list items, but the budget is spent in
	// expanded entries: a user who wrote three rules has no other way
	// to learn why the count is eighteen.
	err.Detail = fmt.Sprintf("must have at most %d entries (a rule with N ports costs N entries)",
		juneauv1alpha1.NetworkACLMaxEntriesPerDirection)
	return field.ErrorList{err}
}

func validateNetworkACLRule(path *field.Path, rule juneauv1alpha1.NetworkACLRule) field.ErrorList {
	var errs field.ErrorList

	switch rule.Action {
	case juneauv1alpha1.NetworkACLActionAllow, juneauv1alpha1.NetworkACLActionDeny:
		// ok
	case "":
		errs = append(errs, field.Required(path.Child("action"), "action is required"))
	default:
		errs = append(errs, field.NotSupported(path.Child("action"), string(rule.Action),
			[]string{string(juneauv1alpha1.NetworkACLActionAllow), string(juneauv1alpha1.NetworkACLActionDeny)}))
	}

	if rule.CIDR == "" {
		errs = append(errs, field.Required(path.Child("cidr"), "cidr is required"))
	} else {
		prefix, err := netip.ParsePrefix(rule.CIDR)
		if err != nil {
			errs = append(errs, field.Invalid(path.Child("cidr"), rule.CIDR, fmt.Sprintf("invalid CIDR: %v", err)))
		} else if !prefix.Addr().Is4() {
			errs = append(errs, field.Invalid(path.Child("cidr"), rule.CIDR, "only IPv4 CIDRs are supported"))
		}
	}

	errs = append(errs, validateNetworkACLProtocolPorts(path, rule.Protocol, rule.Ports)...)
	return errs
}

func validateNetworkACLProtocolPorts(path *field.Path, protocol *intstr.IntOrString, ports []juneauv1alpha1.NetworkACLPort) field.ErrorList {
	var errs field.ErrorList

	proto, err := juneauv1alpha1.ResolveIPProtocol(protocol)
	if err != nil {
		errs = append(errs, field.Invalid(path.Child("protocol"), protocol, err.Error()))
	} else if len(ports) > 0 && !juneauv1alpha1.IPProtocolHasPorts(proto) {
		errs = append(errs, field.Invalid(path.Child("ports"), ports,
			fmt.Sprintf("ports are only valid when protocol is tcp or udp, but protocol is %s",
				juneauv1alpha1.FormatIPProtocol(proto))))
	}

	for i, port := range ports {
		hasPort := port.Port != nil
		hasRange := port.PortRange != nil
		if hasPort == hasRange {
			errs = append(errs, field.Invalid(path.Child("ports").Index(i), port, "exactly one of port or portRange must be set"))
			continue
		}
		if hasRange {
			if port.PortRange.From > port.PortRange.To {
				errs = append(errs, field.Invalid(path.Child("ports").Index(i).Child("portRange", "to"), port.PortRange.To,
					"must be >= portRange.from"))
			}
		}
	}

	return errs
}
