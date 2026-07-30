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
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func SetupNetworkInterfaceAttachmentWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&juneauv1alpha1.NetworkInterfaceAttachment{}).
		WithValidator(&NetworkInterfaceAttachmentCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-networkinterfaceattachment,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=networkinterfaceattachments,verbs=create;update,versions=v1alpha1,name=vnetworkinterfaceattachment-v1alpha1.kb.io,admissionReviewVersions=v1

type NetworkInterfaceAttachmentCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &NetworkInterfaceAttachmentCustomValidator{}

func (v *NetworkInterfaceAttachmentCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	attachment, ok := obj.(*juneauv1alpha1.NetworkInterfaceAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterfaceAttachment object but got %T", obj)
	}

	var networkInterface juneauv1alpha1.NetworkInterface
	if err := v.Get(ctx, client.ObjectKey{
		Namespace: attachment.Namespace,
		Name:      attachment.Spec.NetworkInterfaceRef,
	}, &networkInterface); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, apierrors.NewInvalid(
				schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkInterfaceAttachment"},
				attachment.Name,
				field.ErrorList{field.Invalid(
					field.NewPath("spec", "networkInterfaceRef"),
					attachment.Spec.NetworkInterfaceRef,
					"referenced NetworkInterface does not exist in the same namespace",
				)},
			)
		}
		return nil, err
	}
	return nil, nil
}

func (v *NetworkInterfaceAttachmentCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldAttachment, ok := oldObj.(*juneauv1alpha1.NetworkInterfaceAttachment)
	if !ok {
		return nil, fmt.Errorf("expected an old NetworkInterfaceAttachment object but got %T", oldObj)
	}
	attachment, ok := newObj.(*juneauv1alpha1.NetworkInterfaceAttachment)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkInterfaceAttachment object but got %T", newObj)
	}
	if reflect.DeepEqual(oldAttachment.Spec, attachment.Spec) {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(
		schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "NetworkInterfaceAttachment"},
		attachment.Name,
		field.ErrorList{field.Invalid(field.NewPath("spec"), attachment.Spec, "spec is immutable")},
	)
}

func (v *NetworkInterfaceAttachmentCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	if _, ok := obj.(*juneauv1alpha1.NetworkInterfaceAttachment); !ok {
		return nil, fmt.Errorf("expected a NetworkInterfaceAttachment object but got %T", obj)
	}
	return nil, nil
}
