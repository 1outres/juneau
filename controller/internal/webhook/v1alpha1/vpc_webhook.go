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

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var vpclog = logf.Log.WithName("vpc-resource")

// SetupVpcWebhookWithManager registers the webhook for Vpc in the manager.
func SetupVpcWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.Vpc{}).
		WithValidator(&VpcCustomValidator{}).
		WithDefaulter(&VpcCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-vpc,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcs,verbs=create;update,versions=v1alpha1,name=mvpc-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Vpc when those are created or updated.
type VpcCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &VpcCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Vpc.
func (d *VpcCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)

	if !ok {
		return fmt.Errorf("expected an Vpc object but got %T", obj)
	}
	vpclog.Info("Defaulting for Vpc", "name", vpc.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-vpc,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcs,verbs=create;update;delete,versions=v1alpha1,name=vvpc-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcCustomValidator struct is responsible for validating the Vpc resource
// when it is created, updated, or deleted.
type VpcCustomValidator struct {
}

var _ webhook.CustomValidator = &VpcCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object but got %T", obj)
	}
	vpclog.Info("Validation for Vpc upon creation", "name", vpc.GetName())

	var errs field.ErrorList

	// TODO: Temporary limitation. Remove in future.
	if vpc.Name != "default" {
		errs = append(errs, field.Invalid(field.NewPath("metadata").Child("name"), vpc.Name, "only 'default' is allowed as Vpc name for now"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "Vpc"}, vpc.Name, errs)
		subnetlog.Info("Validation failed for Vpc", "name", vpc.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	vpc, ok := newObj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object for the newObj but got %T", newObj)
	}
	vpclog.Info("Validation for Vpc upon update", "name", vpc.GetName())

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object but got %T", obj)
	}
	vpclog.Info("Validation for Vpc upon deletion", "name", vpc.GetName())

	if vpc.Name == "default" {
		return nil, fmt.Errorf("the default Vpc cannot be deleted")
	}

	return nil, nil
}
