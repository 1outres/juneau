package v1alpha1

import (
	"context"
	"fmt"
	"sort"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpns,verbs=get;list;watch

// SetupVPNWebhookWithManager registers the webhook for VPN in the manager.
func SetupVPNWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneau.VPN{}).
		WithValidator(&VPNCustomValidator{Reader: mgr.GetAPIReader()}).Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-vpn,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=vpns,verbs=create;update;delete,versions=v1alpha1,name=vvpn-v1alpha1.kb.io,admissionReviewVersions=v1

type VPNCustomValidator struct{ client.Reader }

var _ webhook.CustomValidator = &VPNCustomValidator{}

func (v *VPNCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpn, ok := obj.(*juneau.VPN)
	if !ok {
		return nil, fmt.Errorf("expected a VPN but got %T", obj)
	}
	return nil, v.validate(ctx, vpn, nil)
}

func (v *VPNCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	old, ok := oldObj.(*juneau.VPN)
	if !ok {
		return nil, fmt.Errorf("expected an old VPN but got %T", oldObj)
	}
	vpn, ok := newObj.(*juneau.VPN)
	if !ok {
		return nil, fmt.Errorf("expected a new VPN but got %T", newObj)
	}
	return nil, v.validate(ctx, vpn, old)
}

func (v *VPNCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	vpn, ok := obj.(*juneau.VPN)
	if !ok {
		return nil, fmt.Errorf("expected a VPN but got %T", obj)
	}
	var tables juneau.RouteTableList
	if err := v.List(ctx, &tables); err != nil {
		return nil, fmt.Errorf("list RouteTables: %w", err)
	}
	var refs []string
	for _, table := range tables.Items {
		for _, route := range table.Spec.Routes {
			ref := route.Via.VPN
			if route.Via.Type == juneau.ViaVPN && ref != nil && ref.Namespace == vpn.Namespace && ref.Name == vpn.Name {
				refs = append(refs, table.Name)
				break
			}
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	sort.Strings(refs)
	return nil, apierrors.NewForbidden(schema.GroupResource{Group: juneau.GroupVersion.Group, Resource: "vpns"}, vpn.Name,
		fmt.Errorf("RouteTable(s) %v still reference VPN %s/%s", refs, vpn.Namespace, vpn.Name))
}
