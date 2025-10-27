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
	"net"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var subnetleaselog = logf.Log.WithName("subnetlease-resource")

// SetupSubnetLeaseWebhookWithManager registers the webhook for SubnetLease in the manager.
func SetupSubnetLeaseWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.SubnetLease{}).
		WithValidator(&SubnetLeaseCustomValidator{Client: mgr.GetClient()}).
		WithDefaulter(&SubnetLeaseCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-subnetlease,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=subnetleases,verbs=create;update,versions=v1alpha1,name=msubnetlease-v1alpha1.kb.io,admissionReviewVersions=v1

// SubnetLeaseCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind SubnetLease when those are created or updated.
type SubnetLeaseCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &SubnetLeaseCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind SubnetLease.
func (d *SubnetLeaseCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	subnetlease, ok := obj.(*juneauv1alpha1.SubnetLease)

	if !ok {
		return fmt.Errorf("expected an SubnetLease object but got %T", obj)
	}
	subnetleaselog.Info("Defaulting for SubnetLease", "name", subnetlease.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-subnetlease,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=subnetleases,verbs=create;update,versions=v1alpha1,name=vsubnetlease-v1alpha1.kb.io,admissionReviewVersions=v1

// SubnetLeaseCustomValidator struct is responsible for validating the SubnetLease resource
// when it is created, updated, or deleted.
type SubnetLeaseCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &SubnetLeaseCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type SubnetLease.
func (v *SubnetLeaseCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	subnetlease, ok := obj.(*juneauv1alpha1.SubnetLease)
	if !ok {
		return nil, fmt.Errorf("expected a SubnetLease object but got %T", obj)
	}
	subnetleaselog.Info("Validation for SubnetLease upon creation", "name", subnetlease.GetName())

	var errs field.ErrorList

	var subnet juneauv1alpha1.Subnet
	if err := v.Get(ctx, client.ObjectKey{Name: subnetlease.Spec.Subnet}, &subnet); err != nil {
		if errors.IsNotFound(err) {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("subnet"), subnetlease.Spec.Subnet, "referenced Subnet does not exist"))
		} else {
			return nil, err
		}
	}

	_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format in referenced Subnet spec: %v", err)
	}

	ip := net.ParseIP(subnetlease.Spec.IP)
	if ip == nil || !ipnet.Contains(ip) {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("ip"), subnetlease.Spec.IP, "IP address is not valid or not in the referenced Subnet CIDR range"))
	}

	_, err = net.ParseMAC(subnetlease.Spec.MAC)
	if err != nil {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("mac"), subnetlease.Spec.MAC, "invalid MAC address format"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(juneauv1alpha1.GroupVersion.WithKind("SubnetLease").GroupKind(), subnetlease.Name, errs)
		subnetleaselog.Error(err, "Validation failed for SubnetLease upon creation", "name", subnetlease.GetName())
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type SubnetLease.
func (v *SubnetLeaseCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	subnetlease, ok := newObj.(*juneauv1alpha1.SubnetLease)
	if !ok {
		return nil, fmt.Errorf("expected a SubnetLease object for the newObj but got %T", newObj)
	}
	oldSubnetlease, ok := oldObj.(*juneauv1alpha1.SubnetLease)
	if !ok {
		return nil, fmt.Errorf("expected a SubnetLease object for the oldObj but got %T", oldObj)
	}
	subnetleaselog.Info("Validation for SubnetLease upon update", "name", subnetlease.GetName())

	var errs field.ErrorList

	if subnetlease.Spec.Subnet != oldSubnetlease.Spec.Subnet {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("subnet"), subnetlease.Spec.Subnet, "field is immutable"))
	}

	if subnetlease.Spec.IP != oldSubnetlease.Spec.IP {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("ip"), subnetlease.Spec.IP, "field is immutable"))
	}

	if subnetlease.Spec.MAC != oldSubnetlease.Spec.MAC {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("mac"), subnetlease.Spec.MAC, "field is immutable"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(juneauv1alpha1.GroupVersion.WithKind("SubnetLease").GroupKind(), subnetlease.Name, errs)
		subnetleaselog.Error(err, "Validation failed for SubnetLease upon update", "name", subnetlease.GetName())
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type SubnetLease.
func (v *SubnetLeaseCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	subnetlease, ok := obj.(*juneauv1alpha1.SubnetLease)
	if !ok {
		return nil, fmt.Errorf("expected a SubnetLease object but got %T", obj)
	}
	subnetleaselog.Info("Validation for SubnetLease upon deletion", "name", subnetlease.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
