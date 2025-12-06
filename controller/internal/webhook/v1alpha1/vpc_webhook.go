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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var vpclog = logf.Log.WithName("vpc-resource")

// SetupVpcWebhookWithManager registers the webhook for Vpc in the manager.
func SetupVpcWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.Vpc{}).
		WithValidator(&VpcCustomValidator{}).
		WithDefaulter(&VpcCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-vpc,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcs,verbs=create;update,versions=v1alpha1,name=mvpc-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Vpc when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type VpcCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &VpcCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Vpc.
func (d *VpcCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	vpc, ok := obj.(*juneauloutresmev1alpha1.Vpc)

	if !ok {
		return fmt.Errorf("expected an Vpc object but got %T", obj)
	}
	vpclog.Info("Defaulting for Vpc", "name", vpc.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-vpc,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpcs,verbs=create;update,versions=v1alpha1,name=vvpc-v1alpha1.kb.io,admissionReviewVersions=v1

// VpcCustomValidator struct is responsible for validating the Vpc resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type VpcCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &VpcCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpc, ok := obj.(*juneauloutresmev1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object but got %T", obj)
	}
	vpclog.Info("Validation for Vpc upon creation", "name", vpc.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	vpc, ok := newObj.(*juneauloutresmev1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object for the newObj but got %T", newObj)
	}
	vpclog.Info("Validation for Vpc upon update", "name", vpc.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Vpc.
func (v *VpcCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpc, ok := obj.(*juneauloutresmev1alpha1.Vpc)
	if !ok {
		return nil, fmt.Errorf("expected a Vpc object but got %T", obj)
	}
	vpclog.Info("Validation for Vpc upon deletion", "name", vpc.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
