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
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
var externalnetworkattachmentlog = logf.Log.WithName("externalnetworkattachment-resource")

// SetupExternalNetworkAttachmentWebhookWithManager registers the webhook for ExternalNetworkAttachment in the manager.
func SetupExternalNetworkAttachmentWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.ExternalNetworkAttachment{}).
		WithValidator(&ExternalNetworkAttachmentCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&ExternalNetworkAttachmentCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-externalnetworkattachment,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=externalnetworkattachments,verbs=create;update,versions=v1alpha1,name=mexternalnetworkattachment-v1alpha1.kb.io,admissionReviewVersions=v1

// ExternalNetworkAttachmentCustomDefaulter sets defaults for ExternalNetworkAttachment.
type ExternalNetworkAttachmentCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &ExternalNetworkAttachmentCustomDefaulter{}

func (d *ExternalNetworkAttachmentCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	_ = ctx
	if _, ok := obj.(*juneauloutresmev1alpha1.ExternalNetworkAttachment); !ok {
		return fmt.Errorf("expected an ExternalNetworkAttachment object but got %T", obj)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-externalnetworkattachment,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=externalnetworkattachments,verbs=create;update,versions=v1alpha1,name=vexternalnetworkattachment-v1alpha1.kb.io,admissionReviewVersions=v1

// ExternalNetworkAttachmentCustomValidator validates ExternalNetworkAttachment resources.
type ExternalNetworkAttachmentCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &ExternalNetworkAttachmentCustomValidator{}

func (v *ExternalNetworkAttachmentCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	attachment, ok := obj.(*juneauloutresmev1alpha1.ExternalNetworkAttachment)
	if !ok {
		return nil, fmt.Errorf("expected an ExternalNetworkAttachment object but got %T", obj)
	}
	externalnetworkattachmentlog.Info("Validation for ExternalNetworkAttachment upon creation", "name", attachment.GetName())

	return v.validate(ctx, attachment, nil)
}

func (v *ExternalNetworkAttachmentCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	attachment, ok := newObj.(*juneauloutresmev1alpha1.ExternalNetworkAttachment)
	if !ok {
		return nil, fmt.Errorf("expected an ExternalNetworkAttachment object for the newObj but got %T", newObj)
	}
	oldAttachment, ok := oldObj.(*juneauloutresmev1alpha1.ExternalNetworkAttachment)
	if !ok {
		return nil, fmt.Errorf("expected an ExternalNetworkAttachment object for the oldObj but got %T", oldObj)
	}
	externalnetworkattachmentlog.Info("Validation for ExternalNetworkAttachment upon update", "name", attachment.GetName())

	return v.validate(ctx, attachment, oldAttachment)
}

func (v *ExternalNetworkAttachmentCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	attachment, ok := obj.(*juneauloutresmev1alpha1.ExternalNetworkAttachment)
	if !ok {
		return nil, fmt.Errorf("expected an ExternalNetworkAttachment object but got %T", obj)
	}
	externalnetworkattachmentlog.Info("Validation for ExternalNetworkAttachment upon deletion", "name", attachment.GetName())
	return nil, nil
}

func (v *ExternalNetworkAttachmentCustomValidator) validate(ctx context.Context, obj, oldObj *juneauloutresmev1alpha1.ExternalNetworkAttachment) (admission.Warnings, error) {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if oldObj != nil {
		if obj.Spec.ExternalNetwork != oldObj.Spec.ExternalNetwork {
			errs = append(errs, field.Invalid(specPath.Child("externalNetwork"), obj.Spec.ExternalNetwork, "spec.externalNetwork is immutable"))
		}
		if obj.Spec.NodeName != oldObj.Spec.NodeName {
			errs = append(errs, field.Invalid(specPath.Child("nodeName"), obj.Spec.NodeName, "spec.nodeName is immutable"))
		}
	}

	if obj.Spec.ExternalNetwork != "" {
		var externalNetwork juneauloutresmev1alpha1.ExternalNetwork
		if err := v.Get(ctx, client.ObjectKey{Name: obj.Spec.ExternalNetwork}, &externalNetwork); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(specPath.Child("externalNetwork"), obj.Spec.ExternalNetwork, "referenced ExternalNetwork does not exist"))
			} else {
				return nil, err
			}
		} else if externalNetwork.Spec.Type != juneauloutresmev1alpha1.ExternalNetworkTypeBGP {
			errs = append(errs, field.Invalid(specPath.Child("externalNetwork"), obj.Spec.ExternalNetwork, "referenced ExternalNetwork must have type=bgp"))
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "ExternalNetworkAttachment"}, obj.Name, errs)
		externalnetworkattachmentlog.Info("Validation failed for ExternalNetworkAttachment", "name", obj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
