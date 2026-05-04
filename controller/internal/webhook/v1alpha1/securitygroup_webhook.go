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
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
var securitygrouplog = logf.Log.WithName("securitygroup-resource")

// SetupSecurityGroupWebhookWithManager registers the SecurityGroup
// validating webhook.
func SetupSecurityGroupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.SecurityGroup{}).
		WithValidator(&SecurityGroupCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-securitygroup,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=securitygroups,verbs=create;update;delete,versions=v1alpha1,name=vsecuritygroup-v1alpha1.kb.io,admissionReviewVersions=v1

// SecurityGroupCustomValidator enforces structural invariants that the
// CRD schema cannot express:
//
//   - Vpc reference exists and is immutable.
//   - Each peer is exclusively a CIDR or a securityGroupRef (never both).
//   - CIDRs parse as IPv4 prefixes.
//   - Port ranges have from <= to.
//   - When Protocol is icmp/all, ports must not be set.
//   - At delete time, no NetworkInterface still references this SG.
//
// +kubebuilder:object:generate=false
type SecurityGroupCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &SecurityGroupCustomValidator{}

func (v *SecurityGroupCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	sg, ok := obj.(*juneauv1alpha1.SecurityGroup)
	if !ok {
		return nil, fmt.Errorf("expected a SecurityGroup object but got %T", obj)
	}
	return v.validate(ctx, sg, nil)
}

func (v *SecurityGroupCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	sg, ok := newObj.(*juneauv1alpha1.SecurityGroup)
	if !ok {
		return nil, fmt.Errorf("expected a SecurityGroup object for newObj but got %T", newObj)
	}
	old, ok := oldObj.(*juneauv1alpha1.SecurityGroup)
	if !ok {
		return nil, fmt.Errorf("expected a SecurityGroup object for oldObj but got %T", oldObj)
	}
	return v.validate(ctx, sg, old)
}

func (v *SecurityGroupCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	sg, ok := obj.(*juneauv1alpha1.SecurityGroup)
	if !ok {
		return nil, fmt.Errorf("expected a SecurityGroup object but got %T", obj)
	}

	// Refuse delete if any NetworkInterface still references this SG so
	// users do not silently lose their attachment via dangling-reference
	// pruning at reconcile time.
	var ifaces juneauv1alpha1.NetworkInterfaceList
	if err := v.List(ctx, &ifaces); err != nil {
		return nil, err
	}
	for i := range ifaces.Items {
		iface := &ifaces.Items[i]
		for _, ref := range iface.Spec.SecurityGroups {
			if ref == sg.Name {
				return nil, errors.NewForbidden(
					schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "securitygroups"},
					sg.Name,
					fmt.Errorf("SecurityGroup is referenced by NetworkInterface %s/%s", iface.Namespace, iface.Name),
				)
			}
		}
	}

	return nil, nil
}

func (v *SecurityGroupCustomValidator) validate(ctx context.Context, sg, old *juneauv1alpha1.SecurityGroup) (admission.Warnings, error) {
	var errs field.ErrorList

	vpcPath := field.NewPath("spec", "vpc")
	if len(apivalidation.NameIsDNSSubdomain(sg.Spec.Vpc, false)) == 0 {
		var vpc juneauv1alpha1.Vpc
		if err := v.Get(ctx, client.ObjectKey{Name: sg.Spec.Vpc}, &vpc); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(vpcPath, sg.Spec.Vpc, "referenced Vpc does not exist"))
			} else {
				return nil, err
			}
		}
	} else {
		errs = append(errs, field.Invalid(vpcPath, sg.Spec.Vpc, "must be a valid DNS subdomain"))
	}

	if old != nil && sg.Spec.Vpc != old.Spec.Vpc {
		errs = append(errs, field.Invalid(vpcPath, sg.Spec.Vpc, "vpc is immutable"))
	}

	for i, rule := range sg.Spec.Ingress {
		errs = append(errs, validateIngressRule(field.NewPath("spec", "ingress").Index(i), rule)...)
		errs = append(errs, validatePeerSGsInVpc(ctx, v.Client, field.NewPath("spec", "ingress").Index(i).Child("from"), rule.From, sg.Spec.Vpc, sg.Name)...)
	}
	if sg.Spec.Egress != nil {
		for i, rule := range *sg.Spec.Egress {
			errs = append(errs, validateEgressRule(field.NewPath("spec", "egress").Index(i), rule)...)
			errs = append(errs, validatePeerSGsInVpc(ctx, v.Client, field.NewPath("spec", "egress").Index(i).Child("to"), rule.To, sg.Spec.Vpc, sg.Name)...)
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "SecurityGroup"}, sg.Name, errs)
		securitygrouplog.Info("Validation failed for SecurityGroup", "name", sg.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func validateIngressRule(path *field.Path, rule juneauv1alpha1.SecurityGroupIngressRule) field.ErrorList {
	var errs field.ErrorList
	if len(rule.From) == 0 {
		errs = append(errs, field.Required(path.Child("from"), "from must not be empty"))
	}
	for i, peer := range rule.From {
		errs = append(errs, validatePeer(path.Child("from").Index(i), peer)...)
	}
	errs = append(errs, validateProtocolPorts(path, rule.Protocol, rule.Ports)...)
	return errs
}

func validateEgressRule(path *field.Path, rule juneauv1alpha1.SecurityGroupEgressRule) field.ErrorList {
	var errs field.ErrorList
	if len(rule.To) == 0 {
		errs = append(errs, field.Required(path.Child("to"), "to must not be empty"))
	}
	for i, peer := range rule.To {
		errs = append(errs, validatePeer(path.Child("to").Index(i), peer)...)
	}
	errs = append(errs, validateProtocolPorts(path, rule.Protocol, rule.Ports)...)
	return errs
}

func validatePeer(path *field.Path, peer juneauv1alpha1.SecurityGroupPeer) field.ErrorList {
	var errs field.ErrorList
	hasCIDR := peer.CIDR != ""
	hasSG := peer.SecurityGroupRef != nil
	if hasCIDR == hasSG {
		errs = append(errs, field.Invalid(path, peer, "exactly one of cidr or securityGroupRef must be set"))
		return errs
	}
	if hasCIDR {
		prefix, err := netip.ParsePrefix(peer.CIDR)
		if err != nil {
			errs = append(errs, field.Invalid(path.Child("cidr"), peer.CIDR, fmt.Sprintf("invalid CIDR: %v", err)))
		} else if !prefix.Addr().Is4() {
			errs = append(errs, field.Invalid(path.Child("cidr"), peer.CIDR, "only IPv4 CIDRs are supported"))
		}
	}
	if hasSG {
		if len(apivalidation.NameIsDNSSubdomain(peer.SecurityGroupRef.Name, false)) > 0 {
			errs = append(errs, field.Invalid(path.Child("securityGroupRef", "name"), peer.SecurityGroupRef.Name, "must be a valid DNS subdomain"))
		}
	}
	return errs
}

func validateProtocolPorts(path *field.Path, proto juneauv1alpha1.SecurityGroupProtocol, ports []juneauv1alpha1.SecurityGroupPort) field.ErrorList {
	var errs field.ErrorList
	if proto == juneauv1alpha1.SecurityGroupProtocolICMP || proto == juneauv1alpha1.SecurityGroupProtocolAll {
		if len(ports) > 0 {
			errs = append(errs, field.Invalid(path.Child("ports"), ports, "ports must be empty when protocol is icmp or all"))
		}
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
				errs = append(errs, field.Invalid(path.Child("ports").Index(i).Child("portRange", "to"), port.PortRange.To, "must be >= portRange.from"))
			}
		}
	}
	return errs
}

func validatePeerSGsInVpc(ctx context.Context, c client.Client, path *field.Path, peers []juneauv1alpha1.SecurityGroupPeer, vpc, selfName string) field.ErrorList {
	var errs field.ErrorList
	for i, peer := range peers {
		if peer.SecurityGroupRef == nil {
			continue
		}
		if peer.SecurityGroupRef.Name == selfName {
			// Self-reference is permitted (AWS allows it). It means
			// "members of this SG can talk to each other".
			continue
		}
		var ref juneauv1alpha1.SecurityGroup
		if err := c.Get(ctx, client.ObjectKey{Name: peer.SecurityGroupRef.Name}, &ref); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(path.Index(i).Child("securityGroupRef", "name"), peer.SecurityGroupRef.Name, "referenced SecurityGroup does not exist"))
				continue
			}
			// Errors other than NotFound are surfaced as transient server errors, but inside
			// the validator we still emit a field error so admission stays deterministic.
			errs = append(errs, field.InternalError(path.Index(i).Child("securityGroupRef"), err))
			continue
		}
		if ref.Spec.Vpc != vpc {
			errs = append(errs, field.Invalid(path.Index(i).Child("securityGroupRef", "name"), peer.SecurityGroupRef.Name,
				fmt.Sprintf("peer SecurityGroup %q belongs to Vpc %q (expected %q)", ref.Name, ref.Spec.Vpc, vpc)))
		}
	}
	return errs
}
