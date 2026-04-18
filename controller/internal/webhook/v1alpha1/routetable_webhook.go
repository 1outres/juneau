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
var routetablelog = logf.Log.WithName("routetable-resource")

// SetupRouteTableWebhookWithManager registers the webhook for RouteTable in the manager.
func SetupRouteTableWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.RouteTable{}).
		WithValidator(&RouteTableCustomValidator{}).
		WithDefaulter(&RouteTableCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-routetable,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=routetables,verbs=create;update,versions=v1alpha1,name=mroutetable-v1alpha1.kb.io,admissionReviewVersions=v1

// RouteTableCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind RouteTable when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type RouteTableCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &RouteTableCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind RouteTable.
func (d *RouteTableCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	routetable, ok := obj.(*juneauloutresmev1alpha1.RouteTable)

	if !ok {
		return fmt.Errorf("expected an RouteTable object but got %T", obj)
	}
	routetablelog.Info("Defaulting for RouteTable", "name", routetable.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-routetable,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=routetables,verbs=create;update,versions=v1alpha1,name=vroutetable-v1alpha1.kb.io,admissionReviewVersions=v1

// RouteTableCustomValidator struct is responsible for validating the RouteTable resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type RouteTableCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &RouteTableCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type RouteTable.
func (v *RouteTableCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	routetable, ok := obj.(*juneauloutresmev1alpha1.RouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a RouteTable object but got %T", obj)
	}
	routetablelog.Info("Validation for RouteTable upon creation", "name", routetable.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type RouteTable.
func (v *RouteTableCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	routetable, ok := newObj.(*juneauloutresmev1alpha1.RouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a RouteTable object for the newObj but got %T", newObj)
	}
	routetablelog.Info("Validation for RouteTable upon update", "name", routetable.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type RouteTable.
func (v *RouteTableCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	routetable, ok := obj.(*juneauloutresmev1alpha1.RouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a RouteTable object but got %T", obj)
	}
	routetablelog.Info("Validation for RouteTable upon deletion", "name", routetable.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
