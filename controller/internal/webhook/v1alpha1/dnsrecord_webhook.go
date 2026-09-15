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
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apivalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var dnsrecordlog = logf.Log.WithName("dnsrecord-resource")

// SetupDNSRecordWebhookWithManager registers the webhook for DNSRecord in the manager.
func SetupDNSRecordWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.DNSRecord{}).
		WithValidator(&DNSRecordCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&DNSRecordCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-dnsrecord,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=dnsrecords,verbs=create;update,versions=v1alpha1,name=mdnsrecord-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSRecordCustomDefaulter applies DNSRecord defaults.
type DNSRecordCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &DNSRecordCustomDefaulter{}

// Default implements webhook.CustomDefaulter.
func (d *DNSRecordCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	record, ok := obj.(*juneauv1alpha1.DNSRecord)
	if !ok {
		return fmt.Errorf("expected a DNSRecord object but got %T", obj)
	}
	if record.Spec.TTL == nil {
		value := int32(30)
		record.Spec.TTL = &value
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-dnsrecord,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=dnsrecords,verbs=create;update;delete,versions=v1alpha1,name=vdnsrecord-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSRecordCustomValidator validates DNSRecord resources.
type DNSRecordCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &DNSRecordCustomValidator{}

// ValidateCreate validates a new DNSRecord.
func (v *DNSRecordCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	record, ok := obj.(*juneauv1alpha1.DNSRecord)
	if !ok {
		return nil, fmt.Errorf("expected a DNSRecord object but got %T", obj)
	}
	return nil, v.validate(ctx, record, nil)
}

// ValidateUpdate validates a DNSRecord update.
func (v *DNSRecordCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	record, ok := newObj.(*juneauv1alpha1.DNSRecord)
	if !ok {
		return nil, fmt.Errorf("expected a DNSRecord object for newObj but got %T", newObj)
	}
	oldRecord, ok := oldObj.(*juneauv1alpha1.DNSRecord)
	if !ok {
		return nil, fmt.Errorf("expected a DNSRecord object for oldObj but got %T", oldObj)
	}
	return nil, v.validate(ctx, record, oldRecord)
}

func (v *DNSRecordCustomValidator) validate(ctx context.Context, record, oldRecord *juneauv1alpha1.DNSRecord) error {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if record.Spec.Type != juneauv1alpha1.DNSRecordTypeA {
		errs = append(errs, field.NotSupported(specPath.Child("type"), record.Spec.Type, []string{string(juneauv1alpha1.DNSRecordTypeA)}))
	}
	if record.Spec.Name != "@" {
		if messages := apivalidation.IsDNS1123Subdomain(record.Spec.Name); len(messages) > 0 || strings.HasSuffix(record.Spec.Name, ".") {
			errs = append(errs, field.Invalid(specPath.Child("name"), record.Spec.Name, "must be @ or a lowercase relative DNS-1123 subdomain without a trailing dot or wildcard"))
		}
	}
	if record.Spec.TTL != nil && (*record.Spec.TTL < 1 || *record.Spec.TTL > 86400) {
		errs = append(errs, field.Invalid(specPath.Child("ttl"), *record.Spec.TTL, "must be between 1 and 86400"))
	}
	if len(record.Spec.Sources) < 1 || len(record.Spec.Sources) > 100 {
		errs = append(errs, field.Invalid(specPath.Child("sources"), len(record.Spec.Sources), "must contain between 1 and 100 sources"))
	}
	for i := range record.Spec.Sources {
		errs = append(errs, validateDNSRecordSource(record.Spec.Sources[i], specPath.Child("sources").Index(i))...)
	}

	if oldRecord != nil {
		if record.Spec.Zone != oldRecord.Spec.Zone {
			errs = append(errs, field.Invalid(specPath.Child("zone"), record.Spec.Zone, "spec.zone is immutable"))
		}
		if record.Spec.Name != oldRecord.Spec.Name {
			errs = append(errs, field.Invalid(specPath.Child("name"), record.Spec.Name, "spec.name is immutable"))
		}
		if record.Spec.Type != oldRecord.Spec.Type {
			errs = append(errs, field.Invalid(specPath.Child("type"), record.Spec.Type, "spec.type is immutable"))
		}
	}

	if shouldCheckReferences(record) {
		var zone juneauv1alpha1.DNSZone
		if err := v.Get(ctx, client.ObjectKey{Name: record.Spec.Zone}, &zone); err != nil {
			if apierrors.IsNotFound(err) {
				errs = append(errs, field.Invalid(specPath.Child("zone"), record.Spec.Zone, "referenced DNSZone does not exist"))
			} else {
				return fmt.Errorf("get referenced DNSZone: %w", err)
			}
		} else {
			errs = append(errs, validateRecordFQDN(record.Spec.Name, zone.Spec.Domain, specPath.Child("name"))...)
		}

		var records juneauv1alpha1.DNSRecordList
		if err := v.List(ctx, &records); err != nil {
			return fmt.Errorf("list DNSRecords: %w", err)
		}
		for i := range records.Items {
			other := &records.Items[i]
			if other.Name != record.Name && other.Spec.Zone == record.Spec.Zone && other.Spec.Name == record.Spec.Name {
				errs = append(errs, field.Invalid(specPath.Child("name"), record.Spec.Name,
					fmt.Sprintf("DNSRecord %q already uses this name in DNSZone %q", other.Name, record.Spec.Zone)))
				break
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	err := apierrors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "DNSRecord"}, record.Name, errs)
	dnsrecordlog.Info("Validation failed for DNSRecord", "name", record.Name, "error", err)
	return err
}

func validateDNSRecordSource(source juneauv1alpha1.DNSRecordSource, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	count := 0
	if source.IP != nil {
		count++
		parsed, err := netip.ParseAddr(*source.IP)
		if err != nil || !parsed.Is4() {
			errs = append(errs, field.Invalid(path.Child("ip"), *source.IP, "must be an IPv4 address, not a CIDR"))
		}
	}
	if source.NetworkInterface != nil {
		count++
		ref := source.NetworkInterface
		errs = append(errs, validateNamespacedDNSReference(ref.Namespace, ref.Name, path.Child("networkInterface"))...)
	}
	if source.VpcEndpoint != nil {
		count++
		if messages := apivalidation.IsDNS1123Subdomain(source.VpcEndpoint.Name); len(messages) > 0 {
			errs = append(errs, field.Invalid(path.Child("vpcEndpoint").Child("name"), source.VpcEndpoint.Name, "must be a valid resource name"))
		}
	}
	if source.PodSelector != nil {
		count++
		selectorSource := source.PodSelector
		if messages := apivalidation.IsDNS1123Label(selectorSource.Namespace); len(messages) > 0 {
			errs = append(errs, field.Invalid(path.Child("podSelector").Child("namespace"), selectorSource.Namespace, "must be a valid namespace name"))
		}
		if selectorSource.Interface == "" {
			errs = append(errs, field.Required(path.Child("podSelector").Child("interface"), "must not be empty"))
		}
		if len(selectorSource.Selector.MatchLabels) == 0 && len(selectorSource.Selector.MatchExpressions) == 0 {
			errs = append(errs, field.Required(path.Child("podSelector").Child("selector"), "must not be empty"))
		} else if _, err := metav1.LabelSelectorAsSelector(&selectorSource.Selector); err != nil {
			errs = append(errs, field.Invalid(path.Child("podSelector").Child("selector"), selectorSource.Selector, err.Error()))
		}
	}
	if count != 1 {
		errs = append(errs, field.Invalid(path, source, "must set exactly one source kind"))
	}
	return errs
}

func validateNamespacedDNSReference(namespace, name string, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	if messages := apivalidation.IsDNS1123Label(namespace); len(messages) > 0 {
		errs = append(errs, field.Invalid(path.Child("namespace"), namespace, "must be a valid namespace name"))
	}
	if messages := apivalidation.IsDNS1123Subdomain(name); len(messages) > 0 {
		errs = append(errs, field.Invalid(path.Child("name"), name, "must be a valid resource name"))
	}
	return errs
}

func validateRecordFQDN(name, domain string, path *field.Path) field.ErrorList {
	fqdn := domain
	if name != "@" {
		fqdn = name + "." + domain
	}
	if len(fqdn) > 253 || len(apivalidation.IsDNS1123Subdomain(fqdn)) > 0 {
		return field.ErrorList{field.Invalid(path, name, "combined FQDN must be a valid DNS name of at most 253 characters")}
	}
	if dnsNameReserved(fqdn) {
		return field.ErrorList{field.Forbidden(path, "cluster.local is reserved")}
	}
	return nil
}

// ValidateDelete accepts DNSRecord deletion.
func (v *DNSRecordCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	if _, ok := obj.(*juneauv1alpha1.DNSRecord); !ok {
		return nil, fmt.Errorf("expected a DNSRecord object but got %T", obj)
	}
	return nil, nil
}
