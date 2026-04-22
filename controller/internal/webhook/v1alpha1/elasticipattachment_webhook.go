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
// log is for logging in this package.
var elasticipattachmentlog = logf.Log.WithName("elasticipattachment-resource")

// SetupElasticIPAttachmentWebhookWithManager registers the webhook for ElasticIPAttachment in the manager.
func SetupElasticIPAttachmentWebhookWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.ElasticIPAttachment{},
		"spec.elasticIPRef.name",
		func(obj client.Object) []string {
			attachment := obj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
			if attachment.Spec.ElasticIPRef.Name == "" {
				return nil
			}
			return []string{attachment.Spec.ElasticIPRef.Name}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for ElasticIPAttachment.spec.elasticIPRef.name: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.ElasticIPAttachment{},
		"spec.targetRef.networkInterfaceName",
		func(obj client.Object) []string {
			attachment := obj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
			if attachment.Spec.TargetRef.NetworkInterfaceName == "" {
				return nil
			}
			return []string{attachment.Spec.TargetRef.NetworkInterfaceName}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for ElasticIPAttachment.spec.targetRef.networkInterfaceName: %w", err)
	}

	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.ElasticIPAttachment{}).
		WithValidator(&ElasticIPAttachmentCustomValidator{Client: mgr.GetClient()}).
		WithDefaulter(&ElasticIPAttachmentCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-elasticipattachment,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=elasticipattachments,verbs=create;update,versions=v1alpha1,name=melasticipattachment-v1alpha1.kb.io,admissionReviewVersions=v1

// ElasticIPAttachmentCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind ElasticIPAttachment when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type ElasticIPAttachmentCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &ElasticIPAttachmentCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind ElasticIPAttachment.
func (d *ElasticIPAttachmentCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	elasticipattachment, ok := obj.(*juneauloutresmev1alpha1.ElasticIPAttachment)

	if !ok {
		return fmt.Errorf("expected an ElasticIPAttachment object but got %T", obj)
	}
	elasticipattachmentlog.Info("Defaulting for ElasticIPAttachment", "name", elasticipattachment.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-elasticipattachment,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=elasticipattachments,verbs=create;update,versions=v1alpha1,name=velasticipattachment-v1alpha1.kb.io,admissionReviewVersions=v1

// ElasticIPAttachmentCustomValidator struct is responsible for validating the ElasticIPAttachment resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ElasticIPAttachmentCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &ElasticIPAttachmentCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type ElasticIPAttachment.
func (v *ElasticIPAttachmentCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	elasticipattachment, ok := obj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIPAttachment object but got %T", obj)
	}
	elasticipattachmentlog.Info("Validation for ElasticIPAttachment upon creation", "name", elasticipattachment.GetName())

	return v.validate(ctx, elasticipattachment, nil)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type ElasticIPAttachment.
func (v *ElasticIPAttachmentCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	elasticipattachment, ok := newObj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIPAttachment object for the newObj but got %T", newObj)
	}
	oldAttachment, ok := oldObj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIPAttachment object for the oldObj but got %T", oldObj)
	}
	elasticipattachmentlog.Info("Validation for ElasticIPAttachment upon update", "name", elasticipattachment.GetName())

	return v.validate(ctx, elasticipattachment, oldAttachment)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type ElasticIPAttachment.
func (v *ElasticIPAttachmentCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	elasticipattachment, ok := obj.(*juneauloutresmev1alpha1.ElasticIPAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a ElasticIPAttachment object but got %T", obj)
	}
	elasticipattachmentlog.Info("Validation for ElasticIPAttachment upon deletion", "name", elasticipattachment.GetName())

	return nil, nil
}

func (v *ElasticIPAttachmentCustomValidator) validate(ctx context.Context, obj *juneauloutresmev1alpha1.ElasticIPAttachment, oldObj *juneauloutresmev1alpha1.ElasticIPAttachment) (admission.Warnings, error) {
	var errs field.ErrorList

	elasticIPName := obj.Spec.ElasticIPRef.Name
	if elasticIPName != "" {
		var elasticIP juneauloutresmev1alpha1.ElasticIP
		if err := v.Get(ctx, client.ObjectKey{Name: elasticIPName, Namespace: obj.Namespace}, &elasticIP); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(field.NewPath("spec", "elasticIPRef", "name"), elasticIPName, "referenced ElasticIP does not exist in the same namespace"))
			} else {
				return nil, err
			}
		} else if elasticIP.DeletionTimestamp != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec", "elasticIPRef", "name"), elasticIPName, "referenced ElasticIP is being deleted"))
		}
	}

	networkInterfaceName := obj.Spec.TargetRef.NetworkInterfaceName
	if networkInterfaceName != "" {
		var networkInterface juneauloutresmev1alpha1.NetworkInterface
		if err := v.Get(ctx, client.ObjectKey{Name: networkInterfaceName, Namespace: obj.Namespace}, &networkInterface); err != nil {
			if errors.IsNotFound(err) {
				errs = append(errs, field.Invalid(field.NewPath("spec", "targetRef", "networkInterfaceName"), networkInterfaceName, "referenced NetworkInterface does not exist in the same namespace"))
			} else {
				return nil, err
			}
		} else if networkInterface.DeletionTimestamp != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec", "targetRef", "networkInterfaceName"), networkInterfaceName, "referenced NetworkInterface is being deleted"))
		}
	}

	if oldObj != nil {
		if obj.Spec.ElasticIPRef.Name != oldObj.Spec.ElasticIPRef.Name {
			errs = append(errs, field.Invalid(field.NewPath("spec", "elasticIPRef", "name"), obj.Spec.ElasticIPRef.Name, "elasticIPRef.name is immutable"))
		}
		if obj.Spec.TargetRef.NetworkInterfaceName != oldObj.Spec.TargetRef.NetworkInterfaceName {
			errs = append(errs, field.Invalid(field.NewPath("spec", "targetRef", "networkInterfaceName"), obj.Spec.TargetRef.NetworkInterfaceName, "targetRef.networkInterfaceName is immutable"))
		}
	}

	if elasticIPName != "" {
		var byElasticIP juneauloutresmev1alpha1.ElasticIPAttachmentList
		if err := v.List(ctx, &byElasticIP,
			client.InNamespace(obj.Namespace),
			client.MatchingFields{"spec.elasticIPRef.name": elasticIPName},
		); err != nil {
			return nil, err
		}
		for _, attachment := range byElasticIP.Items {
			if attachment.Name == obj.Name {
				continue
			}
			if attachment.DeletionTimestamp != nil {
				continue
			}
			errs = append(errs, field.Invalid(field.NewPath("spec", "elasticIPRef", "name"), elasticIPName, fmt.Sprintf("ElasticIP is already attached by %q", attachment.Name)))
			break
		}
	}

	if networkInterfaceName != "" {
		var byNetworkInterface juneauloutresmev1alpha1.ElasticIPAttachmentList
		if err := v.List(ctx, &byNetworkInterface,
			client.InNamespace(obj.Namespace),
			client.MatchingFields{"spec.targetRef.networkInterfaceName": networkInterfaceName},
		); err != nil {
			return nil, err
		}
		for _, attachment := range byNetworkInterface.Items {
			if attachment.Name == obj.Name {
				continue
			}
			if attachment.DeletionTimestamp != nil {
				continue
			}
			errs = append(errs, field.Invalid(field.NewPath("spec", "targetRef", "networkInterfaceName"), networkInterfaceName, fmt.Sprintf("NetworkInterface already has an attachment %q", attachment.Name)))
			break
		}
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "ElasticIPAttachment"}, obj.Name, errs)
		elasticipattachmentlog.Info("Validation failed for ElasticIPAttachment", "name", obj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
