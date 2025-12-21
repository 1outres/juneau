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

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var ipleaselog = logf.Log.WithName("iplease-resource")

// SetupIPLeaseWebhookWithManager registers the webhook for IPLease in the manager.
func SetupIPLeaseWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.IPLease{}).
		WithValidator(&IPLeaseCustomValidator{}).
		WithDefaulter(&IPLeaseCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-iplease,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=ipleases,verbs=create;update,versions=v1alpha1,name=miplease-v1alpha1.kb.io,admissionReviewVersions=v1

// IPLeaseCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind IPLease when those are created or updated.
type IPLeaseCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &IPLeaseCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind IPLease.
func (d *IPLeaseCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	iplease, ok := obj.(*juneauv1alpha1.IPLease)

	if !ok {
		return fmt.Errorf("expected an IPLease object but got %T", obj)
	}
	ipleaselog.Info("Defaulting for IPLease", "name", iplease.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-iplease,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=ipleases,verbs=create;update,versions=v1alpha1,name=viplease-v1alpha1.kb.io,admissionReviewVersions=v1

// IPLeaseCustomValidator struct is responsible for validating the IPLease resource
// when it is created, updated, or deleted.
type IPLeaseCustomValidator struct {
}

var _ webhook.CustomValidator = &IPLeaseCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type IPLease.
func (v *IPLeaseCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	iplease, ok := obj.(*juneauv1alpha1.IPLease)
	if !ok {
		return nil, fmt.Errorf("expected a IPLease object but got %T", obj)
	}
	ipleaselog.Info("Validation for IPLease upon creation", "name", iplease.GetName())

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type IPLease.
func (v *IPLeaseCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	iplease, ok := newObj.(*juneauv1alpha1.IPLease)
	if !ok {
		return nil, fmt.Errorf("expected a IPLease object for the newObj but got %T", newObj)
	}
	ipleaselog.Info("Validation for IPLease upon update", "name", iplease.GetName())

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type IPLease.
func (v *IPLeaseCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	iplease, ok := obj.(*juneauv1alpha1.IPLease)
	if !ok {
		return nil, fmt.Errorf("expected a IPLease object but got %T", obj)
	}
	ipleaselog.Info("Validation for IPLease upon deletion", "name", iplease.GetName())

	return nil, nil
}
