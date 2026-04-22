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
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
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
// log is for logging in this package.
var elasticiplog = logf.Log.WithName("elasticip-resource")

// SetupElasticIPWebhookWithManager registers the webhook for ElasticIP in the manager.
func SetupElasticIPWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.ElasticIP{}).
		WithValidator(&ElasticIPCustomValidator{Client: mgr.GetClient()}).
		WithDefaulter(&ElasticIPCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-elasticip,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=elasticips,verbs=create;update,versions=v1alpha1,name=melasticip-v1alpha1.kb.io,admissionReviewVersions=v1

// ElasticIPCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind ElasticIP when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type ElasticIPCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &ElasticIPCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind ElasticIP.
func (d *ElasticIPCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	elasticip, ok := obj.(*juneauloutresmev1alpha1.ElasticIP)

	if !ok {
		return fmt.Errorf("expected an ElasticIP object but got %T", obj)
	}
	elasticiplog.Info("Defaulting for ElasticIP", "name", elasticip.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-elasticip,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=elasticips,verbs=create;update;delete,versions=v1alpha1,name=velasticip-v1alpha1.kb.io,admissionReviewVersions=v1

// ElasticIPCustomValidator struct is responsible for validating the ElasticIP resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ElasticIPCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &ElasticIPCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type ElasticIP.
func (v *ElasticIPCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	elasticip, ok := obj.(*juneauloutresmev1alpha1.ElasticIP)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIP object but got %T", obj)
	}
	elasticiplog.Info("Validation for ElasticIP upon creation", "name", elasticip.GetName())

	return v.validate(ctx, elasticip, nil)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type ElasticIP.
func (v *ElasticIPCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	elasticip, ok := newObj.(*juneauloutresmev1alpha1.ElasticIP)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIP object for the newObj but got %T", newObj)
	}
	oldElasticIP, ok := oldObj.(*juneauloutresmev1alpha1.ElasticIP)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIP object for the oldObj but got %T", oldObj)
	}
	elasticiplog.Info("Validation for ElasticIP upon update", "name", elasticip.GetName())

	return v.validate(ctx, elasticip, oldElasticIP)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type ElasticIP.
func (v *ElasticIPCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	elasticip, ok := obj.(*juneauloutresmev1alpha1.ElasticIP)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIP object but got %T", obj)
	}
	elasticiplog.Info("Validation for ElasticIP upon deletion", "name", elasticip.GetName())

	var attachments juneauloutresmev1alpha1.ElasticIPAttachmentList
	if err := v.List(ctx, &attachments, client.InNamespace(elasticip.Namespace)); err != nil {
		return nil, err
	}

	for _, attachment := range attachments.Items {
		if attachment.Spec.ElasticIPRef.Name != elasticip.Name {
			continue
		}
		if attachment.DeletionTimestamp != nil {
			continue
		}
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauloutresmev1alpha1.GroupVersion.Group, Resource: "elasticips"},
			elasticip.Name,
			fmt.Errorf("ElasticIP is referenced by ElasticIPAttachment %q", attachment.Name),
		)
	}

	return nil, nil
}

func (v *ElasticIPCustomValidator) validate(ctx context.Context, obj *juneauloutresmev1alpha1.ElasticIP, oldObj *juneauloutresmev1alpha1.ElasticIP) (admission.Warnings, error) {
	var errs field.ErrorList
	externalNetworkPath := field.NewPath("spec", "externalNetwork")

	if len(apivalidation.NameIsDNSSubdomain(obj.Spec.ExternalNetwork, false)) == 0 {
		var externalNetwork juneauloutresmev1alpha1.ExternalNetwork
		if err := v.Get(ctx, client.ObjectKey{Name: obj.Spec.ExternalNetwork}, &externalNetwork); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(externalNetworkPath, obj.Spec.ExternalNetwork, "referenced ExternalNetwork does not exist"))
			} else {
				return nil, err
			}
		} else if externalNetwork.Spec.Type != juneauloutresmev1alpha1.ExternalNetworkTypeBGP {
			errs = append(errs, field.Invalid(externalNetworkPath, obj.Spec.ExternalNetwork, "referenced ExternalNetwork must have type=bgp"))
		}
	}

	if oldObj != nil && obj.Spec.ExternalNetwork != oldObj.Spec.ExternalNetwork {
		errs = append(errs, field.Invalid(externalNetworkPath, obj.Spec.ExternalNetwork, "externalNetwork is immutable"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "ElasticIP"}, obj.Name, errs)
		elasticiplog.Info("Validation failed for ElasticIP", "name", obj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
