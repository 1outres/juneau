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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

const (
	// ServiceAnnotationVpc selects which Juneau Vpc owns the Service.
	// Absent annotation implies the default Vpc.
	ServiceAnnotationVpc = "juneau.loutres.me/vpc"
	// ServiceAnnotationSubnet is intentionally rejected; Service is a
	// VPC-scoped concept and cannot be tied to a single Subnet.
	ServiceAnnotationSubnet = "juneau.loutres.me/subnet"
	// ServiceAnnotationShared opts a Service in to cross-Vpc visibility:
	// callers in any Vpc with spec.enableService=true can reach the
	// ClusterIP through per-Node SNAT. Only Services owned by the
	// default Vpc may set this annotation, since the data plane's
	// shared-service path is anchored at default-Vpc backends.
	ServiceAnnotationShared = "juneau.loutres.me/shared-service"

	defaultServiceVpc = "default"
)

// nolint:unused
var servicelog = logf.Log.WithName("service-resource")

// SetupServiceWebhookWithManager registers the webhook for core/v1.Service
// in the manager. It validates Juneau-specific annotations on Service
// objects and rejects Services bound to a Vpc that does not have
// spec.enableService=true.
func SetupServiceWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Service{}).
		WithValidator(&ServiceCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate--v1-service,mutating=false,failurePolicy=fail,sideEffects=None,groups="",resources=services,verbs=create;update,versions=v1,name=vservice-juneau-loutres-me.kb.io,admissionReviewVersions=v1

// ServiceCustomValidator validates core/v1.Service objects against Juneau
// constraints. Services pointing at a Vpc with spec.enableService=false
// are rejected so that no Service is silently unreachable.
type ServiceCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &ServiceCustomValidator{}

func (v *ServiceCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("expected a Service object but got %T", obj)
	}

	errs, err := v.validate(ctx, svc)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		return nil, errors.NewInvalid(schema.GroupKind{Kind: "Service"}, svc.Name, errs)
	}

	return nil, nil
}

func (v *ServiceCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	newSvc, ok := newObj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("expected a Service object for newObj but got %T", newObj)
	}
	oldSvc, ok := oldObj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("expected a Service object for oldObj but got %T", oldObj)
	}

	if serviceVpc(newSvc) == serviceVpc(oldSvc) &&
		newSvc.Annotations[ServiceAnnotationSubnet] == oldSvc.Annotations[ServiceAnnotationSubnet] &&
		newSvc.Annotations[ServiceAnnotationShared] == oldSvc.Annotations[ServiceAnnotationShared] {
		// Annotations relevant to Juneau are unchanged. Skip re-validation
		// so that pre-existing Services keep working even if their VPC
		// later loses enableService=true.
		return nil, nil
	}

	errs, err := v.validate(ctx, newSvc)
	if err != nil {
		return nil, err
	}

	if len(errs) > 0 {
		return nil, errors.NewInvalid(schema.GroupKind{Kind: "Service"}, newSvc.Name, errs)
	}

	return nil, nil
}

func (v *ServiceCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_ = ctx
	_ = obj
	return nil, nil
}

func (v *ServiceCustomValidator) validate(ctx context.Context, svc *corev1.Service) (field.ErrorList, error) {
	var errs field.ErrorList
	annPath := field.NewPath("metadata", "annotations")

	if _, hasSubnet := svc.Annotations[ServiceAnnotationSubnet]; hasSubnet {
		errs = append(errs, field.Forbidden(annPath.Key(ServiceAnnotationSubnet), "Service is VPC-scoped; specifying a Subnet is not allowed"))
	}

	vpcName := serviceVpc(svc)
	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: vpcName}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			errs = append(errs, field.Invalid(annPath.Key(ServiceAnnotationVpc), vpcName, "referenced Vpc does not exist"))
			return errs, nil
		}
		return nil, err
	}

	if !vpc.Spec.EnableService {
		errs = append(errs, field.Invalid(annPath.Key(ServiceAnnotationVpc), vpcName, fmt.Sprintf("Vpc %q does not have spec.enableService=true", vpcName)))
	}

	if isSharedServiceAnnotation(svc.Annotations[ServiceAnnotationShared]) && vpcName != defaultServiceVpc {
		// Shared Services route into the default-Vpc fabric (backends and
		// ServiceNATAttachment NetworkEndpoints both live there). Allowing
		// non-default ownership would silently broken the return path.
		errs = append(errs, field.Invalid(annPath.Key(ServiceAnnotationShared), svc.Annotations[ServiceAnnotationShared], "shared-service annotation is only valid on Services owned by the default Vpc"))
	}

	return errs, nil
}

// isSharedServiceAnnotation reports whether the annotation value opts the
// Service in to the shared-service path. Only the canonical "true" enables
// it; any other value (including absent) is treated as opt-out so a
// typo cannot accidentally widen the Service's reachability.
func isSharedServiceAnnotation(value string) bool {
	return value == "true"
}

// serviceVpc returns the Vpc that owns the Service. If the annotation is
// absent, the Service is treated as belonging to the default Vpc.
func serviceVpc(svc *corev1.Service) string {
	if v := svc.Annotations[ServiceAnnotationVpc]; v != "" {
		return v
	}
	return defaultServiceVpc
}
