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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// bgpPeerDefaultPort is the BGP well-known TCP port used when spec.peerPort is not specified.
const bgpPeerDefaultPort uint16 = 179

// nolint:unused
// log is for logging in this package.
var bgppeerlog = logf.Log.WithName("bgppeer-resource")

// SetupBGPPeerWebhookWithManager registers the webhook for BGPPeer in the manager.
func SetupBGPPeerWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauloutresmev1alpha1.BGPPeer{}).
		WithValidator(&BGPPeerCustomValidator{}).
		WithDefaulter(&BGPPeerCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-bgppeer,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=bgppeers,verbs=create;update,versions=v1alpha1,name=mbgppeer-v1alpha1.kb.io,admissionReviewVersions=v1

// BGPPeerCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind BGPPeer when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type BGPPeerCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &BGPPeerCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind BGPPeer.
func (d *BGPPeerCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	bgppeer, ok := obj.(*juneauloutresmev1alpha1.BGPPeer)
	if !ok {
		return fmt.Errorf("expected an BGPPeer object but got %T", obj)
	}
	bgppeerlog.Info("Defaulting for BGPPeer", "name", bgppeer.GetName())

	if bgppeer.Spec.PeerPort == 0 {
		bgppeer.Spec.PeerPort = bgpPeerDefaultPort
	}

	return nil
}

// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-bgppeer,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=bgppeers,verbs=create;update,versions=v1alpha1,name=vbgppeer-v1alpha1.kb.io,admissionReviewVersions=v1

// BGPPeerCustomValidator struct is responsible for validating the BGPPeer resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type BGPPeerCustomValidator struct{}

var _ webhook.CustomValidator = &BGPPeerCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type BGPPeer.
func (v *BGPPeerCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	bgppeer, ok := obj.(*juneauloutresmev1alpha1.BGPPeer)
	if !ok {
		return nil, fmt.Errorf("expected a BGPPeer object but got %T", obj)
	}
	bgppeerlog.Info("Validation for BGPPeer upon creation", "name", bgppeer.GetName())

	return v.validate(bgppeer)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type BGPPeer.
func (v *BGPPeerCustomValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	bgppeer, ok := newObj.(*juneauloutresmev1alpha1.BGPPeer)
	if !ok {
		return nil, fmt.Errorf("expected a BGPPeer object for the newObj but got %T", newObj)
	}
	bgppeerlog.Info("Validation for BGPPeer upon update", "name", bgppeer.GetName())

	return v.validate(bgppeer)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type BGPPeer.
func (v *BGPPeerCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	bgppeer, ok := obj.(*juneauloutresmev1alpha1.BGPPeer)
	if !ok {
		return nil, fmt.Errorf("expected a BGPPeer object but got %T", obj)
	}
	bgppeerlog.Info("Validation for BGPPeer upon deletion", "name", bgppeer.GetName())
	return nil, nil
}

func (v *BGPPeerCustomValidator) validate(newObj *juneauloutresmev1alpha1.BGPPeer) (admission.Warnings, error) {
	var errs field.ErrorList

	if ip := net.ParseIP(newObj.Spec.PeerAddress); ip == nil || ip.To4() == nil {
		errs = append(errs, field.Invalid(field.NewPath("spec", "peerAddress"), newObj.Spec.PeerAddress, "peerAddress must be a valid IPv4"))
	}

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauloutresmev1alpha1.GroupVersion.Group, Kind: "BGPPeer"}, newObj.Name, errs)
		bgppeerlog.Info("Validation failed for BGPPeer", "name", newObj.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}
