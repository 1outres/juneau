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
	"k8s.io/apimachinery/pkg/runtime/schema"
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
var subnetlog = logf.Log.WithName("subnet-resource")

// SetupSubnetWebhookWithManager registers the webhook for Subnet in the manager.
func SetupSubnetWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.Subnet{}).
		WithValidator(&SubnetCustomValidator{Client: mgr.GetClient()}).
		WithDefaulter(&SubnetCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-subnet,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=subnets,verbs=create;update,versions=v1alpha1,name=msubnet-v1alpha1.kb.io,admissionReviewVersions=v1

// SubnetCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Subnet when those are created or updated.
type SubnetCustomDefaulter struct {
}

var _ webhook.CustomDefaulter = &SubnetCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Subnet.
func (d *SubnetCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	subnet, ok := obj.(*juneauv1alpha1.Subnet)

	if !ok {
		return fmt.Errorf("expected an Subnet object but got %T", obj)
	}
	subnetlog.Info("Defaulting for Subnet", "name", subnet.GetName())

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err == nil {
		subnet.Spec.CIDR = cidr.String()
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-subnet,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=subnets,verbs=create;update;delete,versions=v1alpha1,name=vsubnet-v1alpha1.kb.io,admissionReviewVersions=v1

// SubnetCustomValidator struct is responsible for validating the Subnet resource
// when it is created, updated, or deleted.
type SubnetCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &SubnetCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Subnet.
func (v *SubnetCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	subnet, ok := obj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object but got %T", obj)
	}
	subnetlog.Info("Validation for Subnet upon creation", "name", subnet.GetName())

	var errs field.ErrorList

	var vpc juneauv1alpha1.Vpc
	if err := v.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("vpc"), subnet.Spec.Vpc, "referenced Vpc does not exist"))
		} else {
			return nil, err
		}
	}
	if subnet.Name == "default" && subnet.Spec.Vpc != "default" {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("vpc"), subnet.Spec.Vpc, "the default Subnet must reference the default Vpc"))
	}
	if subnet.Spec.Vpc == "default" && subnet.Name != "default" {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("vpc"), subnet.Spec.Vpc, "only the default Subnet can reference the default Vpc"))
	}

	_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("cidr"), subnet.Spec.CIDR, "invalid CIDR format"))
	}

	if ipnet.IP.To4() == nil {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("cidr"), subnet.Spec.CIDR, "only IPv4 CIDR blocks are supported"))
	} else if ones, _ := ipnet.Mask.Size(); ones > 28 {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("cidr"), subnet.Spec.CIDR, "CIDR block must allow for at least 14 usable IP addresses (/28 or larger)"))
	} else if ones, _ := ipnet.Mask.Size(); ones < 16 {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("cidr"), subnet.Spec.CIDR, "CIDR block must be /16 or larger"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "Subnet"}, subnet.Name, errs)
		subnetlog.Info("Validation failed for Subnet", "name", subnet.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Subnet.
func (v *SubnetCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	subnet, ok := newObj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object for the newObj but got %T", newObj)
	}
	oldSubnet, ok := oldObj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object for the oldObj but got %T", oldObj)
	}
	subnetlog.Info("Validation for Subnet upon update", "name", subnet.GetName())

	var errs field.ErrorList

	if subnet.Spec.Vpc != oldSubnet.Spec.Vpc {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("vpc"), subnet.Spec.Vpc, "changing the Vpc of a Subnet is not allowed"))
	}

	if subnet.Spec.CIDR != oldSubnet.Spec.CIDR {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("cidr"), subnet.Spec.CIDR, "changing the CIDR of a Subnet is not allowed"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "Subnet"}, subnet.Name, errs)
		subnetlog.Info("Validation failed for Subnet", "name", subnet.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Subnet.
func (v *SubnetCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	subnet, ok := obj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil, fmt.Errorf("expected a Subnet object but got %T", obj)
	}
	subnetlog.Info("Validation for Subnet upon deletion", "name", subnet.GetName())

	if subnet.Name == "default" {
		return nil, fmt.Errorf("the default Subnet cannot be deleted")
	}

	return nil, nil
}
