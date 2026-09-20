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
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

var dnszonelog = logf.Log.WithName("dnszone-resource")

// SetupDNSZoneWebhookWithManager registers the webhook for DNSZone in the manager.
func SetupDNSZoneWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.DNSZone{}).
		WithValidator(&DNSZoneCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&DNSZoneCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-dnszone,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=dnszones,verbs=create;update,versions=v1alpha1,name=mdnszone-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSZoneCustomDefaulter applies DNSZone defaults.
type DNSZoneCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &DNSZoneCustomDefaulter{}

// Default implements webhook.CustomDefaulter.
func (d *DNSZoneCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	if _, ok := obj.(*juneauv1alpha1.DNSZone); !ok {
		return fmt.Errorf("expected a DNSZone object but got %T", obj)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-dnszone,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=dnszones,verbs=create;update;delete,versions=v1alpha1,name=vdnszone-v1alpha1.kb.io,admissionReviewVersions=v1

// DNSZoneCustomValidator validates DNSZone resources.
type DNSZoneCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &DNSZoneCustomValidator{}

// ValidateCreate validates a new DNSZone.
func (v *DNSZoneCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	zone, ok := obj.(*juneauv1alpha1.DNSZone)
	if !ok {
		return nil, fmt.Errorf("expected a DNSZone object but got %T", obj)
	}
	return nil, v.validate(ctx, zone, nil)
}

// ValidateUpdate validates a DNSZone update.
func (v *DNSZoneCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	zone, ok := newObj.(*juneauv1alpha1.DNSZone)
	if !ok {
		return nil, fmt.Errorf("expected a DNSZone object for newObj but got %T", newObj)
	}
	oldZone, ok := oldObj.(*juneauv1alpha1.DNSZone)
	if !ok {
		return nil, fmt.Errorf("expected a DNSZone object for oldObj but got %T", oldObj)
	}
	return nil, v.validate(ctx, zone, oldZone)
}

func (v *DNSZoneCustomValidator) validate(ctx context.Context, zone, oldZone *juneauv1alpha1.DNSZone) error {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if messages := apivalidation.IsDNS1123Subdomain(zone.Spec.Domain); len(messages) > 0 || strings.HasSuffix(zone.Spec.Domain, ".") {
		errs = append(errs, field.Invalid(specPath.Child("domain"), zone.Spec.Domain, "must be a lowercase DNS-1123 subdomain without a trailing dot"))
	}
	if dnsNameReserved(zone.Spec.Domain) {
		errs = append(errs, field.Forbidden(specPath.Child("domain"), "cluster.local and its descendants are reserved"))
	}

	if oldZone != nil {
		if zone.Spec.Vpc != oldZone.Spec.Vpc {
			errs = append(errs, field.Invalid(specPath.Child("vpc"), zone.Spec.Vpc, "spec.vpc is immutable"))
		}
		if zone.Spec.Domain != oldZone.Spec.Domain {
			errs = append(errs, field.Invalid(specPath.Child("domain"), zone.Spec.Domain, "spec.domain is immutable"))
		}
	}

	if shouldCheckReferences(zone) {
		var vpc juneauv1alpha1.Vpc
		if err := v.Get(ctx, client.ObjectKey{Name: zone.Spec.Vpc}, &vpc); err != nil {
			if apierrors.IsNotFound(err) {
				errs = append(errs, field.Invalid(specPath.Child("vpc"), zone.Spec.Vpc, "referenced Vpc does not exist"))
			} else {
				return fmt.Errorf("get referenced Vpc: %w", err)
			}
		}

		var zones juneauv1alpha1.DNSZoneList
		if err := v.List(ctx, &zones); err != nil {
			return fmt.Errorf("list DNSZones: %w", err)
		}
		for i := range zones.Items {
			other := &zones.Items[i]
			if other.Name != zone.Name && other.Spec.Vpc == zone.Spec.Vpc && other.Spec.Domain == zone.Spec.Domain {
				errs = append(errs, field.Invalid(specPath.Child("domain"), zone.Spec.Domain,
					fmt.Sprintf("DNSZone %q already uses this domain in Vpc %q", other.Name, zone.Spec.Vpc)))
				break
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	err := apierrors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "DNSZone"}, zone.Name, errs)
	dnszonelog.Info("Validation failed for DNSZone", "name", zone.Name, "error", err)
	return err
}

// ValidateDelete rejects deleting a DNSZone that still has DNSRecords.
func (v *DNSZoneCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	zone, ok := obj.(*juneauv1alpha1.DNSZone)
	if !ok {
		return nil, fmt.Errorf("expected a DNSZone object but got %T", obj)
	}

	var records juneauv1alpha1.DNSRecordList
	if err := v.List(ctx, &records); err != nil {
		return nil, fmt.Errorf("list DNSRecords: %w", err)
	}
	refs := make([]string, 0)
	for i := range records.Items {
		if records.Items[i].Spec.Zone == zone.Name {
			refs = append(refs, records.Items[i].Name)
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewForbidden(
		schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "dnszones"},
		zone.Name,
		fmt.Errorf("DNSRecord(s) %v still reference this DNSZone; delete them first", refs),
	)
}

func dnsNameReserved(name string) bool {
	return name == "cluster.local" || strings.HasSuffix(name, ".cluster.local")
}
