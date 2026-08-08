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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var transitgatewaylog = logf.Log.WithName("transitgateway-resource")

// SetupTransitGatewayWebhookWithManager registers the webhook for TransitGateway in the manager.
func SetupTransitGatewayWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.TransitGateway{}).
		WithValidator(&TransitGatewayCustomValidator{Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-transitgateway,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=transitgateways,verbs=create;update;delete,versions=v1alpha1,name=vtransitgateway-v1alpha1.kb.io,admissionReviewVersions=v1

// TransitGatewayCustomValidator validates TransitGateway resources.
//
// +kubebuilder:object:generate=false
type TransitGatewayCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &TransitGatewayCustomValidator{}

// ValidateCreate accepts every TransitGateway. The spec carries no
// fields, so there is nothing to check before the reconciler builds the
// default route table.
func (v *TransitGatewayCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	transitGateway, ok := obj.(*juneauv1alpha1.TransitGateway)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGateway object but got %T", obj)
	}
	transitgatewaylog.Info("Validation for TransitGateway upon creation", "name", transitGateway.GetName())

	return nil, nil
}

func (v *TransitGatewayCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	_ = ctx

	transitGateway, ok := newObj.(*juneauv1alpha1.TransitGateway)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGateway object for the newObj but got %T", newObj)
	}
	transitgatewaylog.Info("Validation for TransitGateway upon update", "name", transitGateway.GetName())

	return nil, nil
}

func (v *TransitGatewayCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	transitGateway, ok := obj.(*juneauv1alpha1.TransitGateway)
	if !ok {
		return nil, fmt.Errorf("expected a TransitGateway object but got %T", obj)
	}
	transitgatewaylog.Info("Validation for TransitGateway upon deletion", "name", transitGateway.GetName())

	// Block deletion while a Vpc is still attached. The attachment would
	// keep pointing at a gateway that no longer exists and its Ready
	// condition could never recover.
	var attachmentList juneauv1alpha1.TransitGatewayAttachmentList
	if err := v.List(ctx, &attachmentList); err != nil {
		return nil, fmt.Errorf("list TransitGatewayAttachments: %w", err)
	}
	var attachmentRefs []string
	for i := range attachmentList.Items {
		if attachmentList.Items[i].Spec.TransitGateway == transitGateway.Name {
			attachmentRefs = append(attachmentRefs, attachmentList.Items[i].Name)
		}
	}
	if len(attachmentRefs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "transitgateways"},
			transitGateway.Name,
			fmt.Errorf("TransitGatewayAttachment(s) %v are still attached to this TransitGateway; delete them first", attachmentRefs),
		)
	}

	// Block deletion while a RouteTable still routes through this
	// gateway, the same guard VpcPeering uses: those routes would stop
	// resolving with no object left to point the operator at.
	var routeTableList juneauv1alpha1.RouteTableList
	if err := v.List(ctx, &routeTableList); err != nil {
		return nil, fmt.Errorf("list RouteTables: %w", err)
	}
	var routeRefs []string
	for _, routeTable := range routeTableList.Items {
		for _, route := range routeTable.Spec.Routes {
			if route.Via.Type == juneauv1alpha1.ViaTransitGateway && route.Via.TransitGateway == transitGateway.Name {
				routeRefs = append(routeRefs, routeTable.Name)
				break
			}
		}
	}
	if len(routeRefs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "transitgateways"},
			transitGateway.Name,
			fmt.Errorf("RouteTable(s) %v still references this TransitGateway via spec.routes[].via.transitGateway", routeRefs),
		)
	}

	return nil, nil
}
