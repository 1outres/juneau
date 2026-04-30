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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
var servicenatattachmentlog = logf.Log.WithName("servicenatattachment-resource")

// SetupServiceNATAttachmentWebhookWithManager registers the webhook for ServiceNATAttachment in the manager.
func SetupServiceNATAttachmentWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.ServiceNATAttachment{}).
		WithValidator(&ServiceNATAttachmentCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-servicenatattachment,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=servicenatattachments,verbs=create;update,versions=v1alpha1,name=vservicenatattachment-v1alpha1.kb.io,admissionReviewVersions=v1

// ServiceNATAttachmentCustomValidator validates ServiceNATAttachment
// resources. Each attachment is keyed by Node name; both the metadata
// name and spec.nodeName must agree, and spec.nodeName is immutable.
type ServiceNATAttachmentCustomValidator struct{}

var _ webhook.CustomValidator = &ServiceNATAttachmentCustomValidator{}

func (v *ServiceNATAttachmentCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	attachment, ok := obj.(*juneauloutresmev1alpha1.ServiceNATAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ServiceNATAttachment object but got %T", obj)
	}
	servicenatattachmentlog.Info("Validation for ServiceNATAttachment upon creation", "name", attachment.GetName())
	return validateServiceNATAttachment(attachment, nil)
}

func (v *ServiceNATAttachmentCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	attachment, ok := newObj.(*juneauloutresmev1alpha1.ServiceNATAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ServiceNATAttachment object for the newObj but got %T", newObj)
	}
	oldAttachment, ok := oldObj.(*juneauloutresmev1alpha1.ServiceNATAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ServiceNATAttachment object for the oldObj but got %T", oldObj)
	}
	servicenatattachmentlog.Info("Validation for ServiceNATAttachment upon update", "name", attachment.GetName())
	return validateServiceNATAttachment(attachment, oldAttachment)
}

func (v *ServiceNATAttachmentCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	attachment, ok := obj.(*juneauloutresmev1alpha1.ServiceNATAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ServiceNATAttachment object but got %T", obj)
	}
	servicenatattachmentlog.Info("Validation for ServiceNATAttachment upon deletion", "name", attachment.GetName())
	return nil, nil
}

func validateServiceNATAttachment(obj, oldObj *juneauloutresmev1alpha1.ServiceNATAttachment) (admission.Warnings, error) {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if obj.Spec.NodeName != obj.Name {
		errs = append(errs, field.Invalid(specPath.Child("nodeName"), obj.Spec.NodeName, "spec.nodeName must equal metadata.name"))
	}

	if oldObj != nil && obj.Spec.NodeName != oldObj.Spec.NodeName {
		errs = append(errs, field.Invalid(specPath.Child("nodeName"), obj.Spec.NodeName, "spec.nodeName is immutable"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "ServiceNATAttachment"}, obj.Name, errs)
		servicenatattachmentlog.Info("Validation failed for ServiceNATAttachment", "name", obj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
