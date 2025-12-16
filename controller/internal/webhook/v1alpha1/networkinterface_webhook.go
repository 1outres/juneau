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
var networkinterfacelog = logf.Log.WithName("networkinterface-resource")

// SetupNetworkInterfaceWebhookWithManager registers the webhook for NetworkInterface in the manager.
func SetupNetworkInterfaceWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.NetworkInterface{}).
		WithValidator(&NetworkInterfaceCustomValidator{}).
		WithDefaulter(&NetworkInterfaceCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-networkinterface,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkinterfaces,verbs=create;update,versions=v1alpha1,name=mnetworkinterface-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkInterfaceCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind NetworkInterface when those are created or updated.
type NetworkInterfaceCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &NetworkInterfaceCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind NetworkInterface.
func (d *NetworkInterfaceCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	networkinterface, ok := obj.(*juneauloutresmev1alpha1.NetworkInterface)

	if !ok {
		return fmt.Errorf("expected an NetworkInterface object but got %T", obj)
	}
	networkinterfacelog.Info("Defaulting for NetworkInterface", "name", networkinterface.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-networkinterface,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkinterfaces,verbs=create;update,versions=v1alpha1,name=vnetworkinterface-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkInterfaceCustomValidator struct is responsible for validating the NetworkInterface resource
// when it is created, updated, or deleted.
type NetworkInterfaceCustomValidator struct {
}

var _ webhook.CustomValidator = &NetworkInterfaceCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NetworkInterface.
func (v *NetworkInterfaceCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	networkinterface, ok := obj.(*juneauloutresmev1alpha1.NetworkInterface)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterface object but got %T", obj)
	}
	networkinterfacelog.Info("Validation for NetworkInterface upon creation", "name", networkinterface.GetName())

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NetworkInterface.
func (v *NetworkInterfaceCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	networkinterface, ok := newObj.(*juneauloutresmev1alpha1.NetworkInterface)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterface object for the newObj but got %T", newObj)
	}
	networkinterfacelog.Info("Validation for NetworkInterface upon update", "name", networkinterface.GetName())

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NetworkInterface.
func (v *NetworkInterfaceCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	networkinterface, ok := obj.(*juneauloutresmev1alpha1.NetworkInterface)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterface object but got %T", obj)
	}
	networkinterfacelog.Info("Validation for NetworkInterface upon deletion", "name", networkinterface.GetName())

	return nil, nil
}
