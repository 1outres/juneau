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
var routetablelog = logf.Log.WithName("routetable-resource")

// SetupRouteTableWebhookWithManager registers the webhook for RouteTable in the manager.
func SetupRouteTableWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&juneauv1alpha1.RouteTable{}).
		WithValidator(&RouteTableCustomValidator{Reader: mgr.GetAPIReader()}).
		WithDefaulter(&RouteTableCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-juneau-loutres-me-v1alpha1-routetable,mutating=true,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=routetables,verbs=create;update,versions=v1alpha1,name=mroutetable-v1alpha1.kb.io,admissionReviewVersions=v1

// RouteTableCustomDefaulter sets defaults for RouteTable.
type RouteTableCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &RouteTableCustomDefaulter{}

func (d *RouteTableCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	_ = ctx

	if _, ok := obj.(*juneauv1alpha1.RouteTable); !ok {
		return fmt.Errorf("expected a RouteTable object but got %T", obj)
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-juneau-loutres-me-v1alpha1-routetable,mutating=false,failurePolicy=fail,sideEffects=None,groups=juneau.loutres.me,resources=routetables,verbs=create;update;delete,versions=v1alpha1,name=vroutetable-v1alpha1.kb.io,admissionReviewVersions=v1

// RouteTableCustomValidator validates RouteTable resources.
type RouteTableCustomValidator struct {
	client.Reader
}

var _ webhook.CustomValidator = &RouteTableCustomValidator{}

func (v *RouteTableCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	routeTable, ok := obj.(*juneauv1alpha1.RouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a RouteTable object but got %T", obj)
	}
	routetablelog.Info("Validation for RouteTable upon creation", "name", routeTable.GetName())

	err := v.validateRouteTable(ctx, routeTable)
	if err != nil {
		routetablelog.Info("Validation failed for RouteTable", "name", routeTable.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func (v *RouteTableCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	routeTable, ok := newObj.(*juneauv1alpha1.RouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a RouteTable object for the newObj but got %T", newObj)
	}
	oldRouteTable, ok := oldObj.(*juneauv1alpha1.RouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a RouteTable object for the oldObj but got %T", oldObj)
	}
	routetablelog.Info("Validation for RouteTable upon update", "name", routeTable.GetName())

	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if routeTable.Spec.Vpc != oldRouteTable.Spec.Vpc {
		errs = append(errs, field.Invalid(specPath.Child("vpc"), routeTable.Spec.Vpc, "spec.vpc is immutable"))
	}
	errList, err := v.validateRouteTableSpec(ctx, routeTable, specPath)
	if err != nil {
		return nil, err
	}
	errs = append(errs, errList...)

	if len(errs) > 0 {
		err := errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "RouteTable"}, routeTable.Name, errs)
		routetablelog.Info("Validation failed for RouteTable", "name", routeTable.GetName(), "error", err)
		return nil, err
	}

	return nil, nil
}

func (v *RouteTableCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	routeTable, ok := obj.(*juneauv1alpha1.RouteTable)
	if !ok {
		return nil, fmt.Errorf("expected a RouteTable object but got %T", obj)
	}
	routetablelog.Info("Validation for RouteTable upon deletion", "name", routeTable.GetName())

	// Block deleting the Vpc's main RouteTable: the VpcReconciler would
	// recreate it on the next reconcile anyway, but the gap leaves
	// Subnets without a route table to resolve and triggers spurious
	// daemon errors. Once the owning Vpc is itself being deleted we must
	// let the garbage collector cascade-delete this RouteTable (the Vpc
	// owns it): a foreground cascade leaves the Vpc in etcd with a
	// deletionTimestamp until its owned RouteTable is gone, so rejecting
	// the delete here would deadlock the Vpc's own deletion.
	var vpc juneauv1alpha1.Vpc
	switch err := v.Get(ctx, client.ObjectKey{Name: routeTable.Name}, &vpc); {
	case err == nil:
		if vpc.DeletionTimestamp.IsZero() {
			return nil, errors.NewForbidden(
				schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "routetables"},
				routeTable.Name,
				fmt.Errorf("RouteTable %q is the main RouteTable of Vpc %q; delete the Vpc first", routeTable.Name, vpc.Name),
			)
		}
	case !errors.IsNotFound(err):
		return nil, fmt.Errorf("look up Vpc %q: %w", routeTable.Name, err)
	}

	// Block deletion while any Subnet still references this RouteTable
	// via spec.routeTable. Without this guard the daemon would lose its
	// table_id mapping and stop programming the FIB for those Subnets.
	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, fmt.Errorf("list Subnets: %w", err)
	}
	var refs []string
	for _, subnet := range subnetList.Items {
		if subnet.Spec.RouteTable == routeTable.Name {
			refs = append(refs, subnet.Name)
		}
	}
	if len(refs) > 0 {
		return nil, errors.NewForbidden(
			schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "routetables"},
			routeTable.Name,
			fmt.Errorf("Subnet(s) %v still references this RouteTable via spec.routeTable", refs),
		)
	}

	return nil, nil
}

func (v *RouteTableCustomValidator) validateRouteTable(ctx context.Context, routeTable *juneauv1alpha1.RouteTable) error {
	specPath := field.NewPath("spec")
	errList, err := v.validateRouteTableSpec(ctx, routeTable, specPath)
	if err != nil {
		return err
	}
	if len(errList) == 0 {
		return nil
	}

	return errors.NewInvalid(schema.GroupKind{Group: juneauv1alpha1.GroupVersion.Group, Kind: "RouteTable"}, routeTable.Name, errList)
}

func (v *RouteTableCustomValidator) validateRouteTableSpec(ctx context.Context, routeTable *juneauv1alpha1.RouteTable, specPath *field.Path) (field.ErrorList, error) {
	var errs field.ErrorList
	spec := &routeTable.Spec

	if spec.Vpc == "" {
		errs = append(errs, field.Required(specPath.Child("vpc"), "spec.vpc is required"))
	}

	connectedRoutes := map[string]string{}
	if shouldCheckReferences(routeTable) {
		var err error
		connectedRoutes, err = v.listConnectedRoutes(ctx, spec.Vpc)
		if err != nil {
			return nil, err
		}
	}

	seenDst := map[string]struct{}{}
	for i, route := range spec.Routes {
		routePath := specPath.Child("routes").Index(i)
		switch route.Via.Type {
		case juneauv1alpha1.ViaEndpoint:
			if route.Via.Endpoint == "" {
				errs = append(errs, field.Required(routePath.Child("via", "endpointName"), "spec.routes[].via.endpointName is required when via.type is endpoint"))
			}
			if route.Via.NATGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "natGateway"), route.Via.NATGateway, "spec.routes[].via.natGateway must be empty when via.type is endpoint"))
			}
			if route.Via.VpcPeering != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "vpcPeering"), route.Via.VpcPeering, "spec.routes[].via.vpcPeering must be empty when via.type is endpoint"))
			}
			if route.Via.TransitGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "transitGateway"), route.Via.TransitGateway, "spec.routes[].via.transitGateway must be empty when via.type is endpoint"))
			}
		case juneauv1alpha1.ViaConnected, juneauv1alpha1.ViaInternetGateway:
			if route.Via.Endpoint != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "endpointName"), route.Via.Endpoint, fmt.Sprintf("spec.routes[].via.endpointName must be empty when via.type is %q", route.Via.Type)))
			}
			if route.Via.NATGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "natGateway"), route.Via.NATGateway, fmt.Sprintf("spec.routes[].via.natGateway must be empty when via.type is %q", route.Via.Type)))
			}
			if route.Via.VpcPeering != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "vpcPeering"), route.Via.VpcPeering, fmt.Sprintf("spec.routes[].via.vpcPeering must be empty when via.type is %q", route.Via.Type)))
			}
			if route.Via.TransitGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "transitGateway"), route.Via.TransitGateway, fmt.Sprintf("spec.routes[].via.transitGateway must be empty when via.type is %q", route.Via.Type)))
			}
		case juneauv1alpha1.ViaService:
			errs = append(errs, field.Forbidden(routePath.Child("via", "type"), "spec.routes[].via.type=service is managed by the controller and cannot be specified manually; configure spec.service on the Vpc instead"))
		case juneauv1alpha1.ViaVpcEndpoint:
			errs = append(errs, field.Forbidden(routePath.Child("via", "type"), "spec.routes[].via.type=vpcEndpoint is managed by the controller and cannot be specified manually; configure spec.endpointPool on the Vpc instead"))
		case juneauv1alpha1.ViaNATGateway:
			if route.Via.NATGateway == "" {
				errs = append(errs, field.Required(routePath.Child("via", "natGateway"), "spec.routes[].via.natGateway is required when via.type is natGateway"))
			}
			if route.Via.Endpoint != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "endpointName"), route.Via.Endpoint, "spec.routes[].via.endpointName must be empty when via.type is natGateway"))
			}
			if route.Via.VpcPeering != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "vpcPeering"), route.Via.VpcPeering, "spec.routes[].via.vpcPeering must be empty when via.type is natGateway"))
			}
			if route.Via.TransitGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "transitGateway"), route.Via.TransitGateway, "spec.routes[].via.transitGateway must be empty when via.type is natGateway"))
			}
		case juneauv1alpha1.ViaVpcPeering:
			if route.Via.VpcPeering == "" {
				errs = append(errs, field.Required(routePath.Child("via", "vpcPeering"), "spec.routes[].via.vpcPeering is required when via.type is vpcPeering"))
			}
			if route.Via.Endpoint != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "endpointName"), route.Via.Endpoint, "spec.routes[].via.endpointName must be empty when via.type is vpcPeering"))
			}
			if route.Via.NATGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "natGateway"), route.Via.NATGateway, "spec.routes[].via.natGateway must be empty when via.type is vpcPeering"))
			}
			if route.Via.TransitGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "transitGateway"), route.Via.TransitGateway, "spec.routes[].via.transitGateway must be empty when via.type is vpcPeering"))
			}
		case juneauv1alpha1.ViaTransitGateway:
			if route.Via.TransitGateway == "" {
				errs = append(errs, field.Required(routePath.Child("via", "transitGateway"), "spec.routes[].via.transitGateway is required when via.type is transitGateway"))
			}
			if route.Via.Endpoint != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "endpointName"), route.Via.Endpoint, "spec.routes[].via.endpointName must be empty when via.type is transitGateway"))
			}
			if route.Via.NATGateway != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "natGateway"), route.Via.NATGateway, "spec.routes[].via.natGateway must be empty when via.type is transitGateway"))
			}
			if route.Via.VpcPeering != "" {
				errs = append(errs, field.Invalid(routePath.Child("via", "vpcPeering"), route.Via.VpcPeering, "spec.routes[].via.vpcPeering must be empty when via.type is transitGateway"))
			}
		}

		if _, ok := seenDst[route.Dst]; ok {
			errs = append(errs, field.Duplicate(routePath.Child("dst"), route.Dst))
			continue
		}
		seenDst[route.Dst] = struct{}{}

		if subnetName, ok := connectedRoutes[route.Dst]; ok {
			errs = append(errs, field.Invalid(routePath.Child("dst"), route.Dst, fmt.Sprintf("duplicates connected route for Subnet %q in Vpc %q", subnetName, spec.Vpc)))
		}
	}

	return errs, nil
}

func (v *RouteTableCustomValidator) listConnectedRoutes(ctx context.Context, vpcName string) (map[string]string, error) {
	connectedRoutes := map[string]string{}
	if vpcName == "" {
		return connectedRoutes, nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := v.List(ctx, &subnetList); err != nil {
		return nil, err
	}

	for _, subnet := range subnetList.Items {
		if subnet.Spec.Vpc != vpcName {
			continue
		}
		connectedRoutes[subnet.Spec.CIDR] = subnet.Name
	}

	return connectedRoutes, nil
}
