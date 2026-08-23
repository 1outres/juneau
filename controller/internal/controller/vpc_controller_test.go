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

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Vpc main RouteTable write races", func() {
	ctx := context.Background()

	routeTableResource := schema.GroupResource{
		Group:    juneauv1alpha1.GroupVersion.Group,
		Resource: "routetables",
	}

	// The Vpc is named "default" so Reconcile short-circuits the VPC ID
	// allocation and reaches the main RouteTable write straight away.
	newReadyVpc := func() *juneauv1alpha1.Vpc {
		vpc := &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultVpcName,
				UID:  types.UID("vpc-main-route-table-race"),
			},
			Status: juneauv1alpha1.VpcStatus{
				MainRouteTable: defaultVpcName,
				VpcID:          1,
			},
		}
		meta.SetStatusCondition(&vpc.Status.Conditions, metav1.Condition{
			Type:   juneauv1alpha1.VpcStatusReady,
			Status: metav1.ConditionTrue,
			Reason: vpcReasonReconcileSucceeded,
		})
		return vpc
	}

	newReconciler := func(objects []client.Object, funcs interceptor.Funcs) (*VpcReconciler, client.Client) {
		testScheme := runtime.NewScheme()
		Expect(juneauv1alpha1.AddToScheme(testScheme)).To(Succeed())

		c := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(objects...).
			WithStatusSubresource(&juneauv1alpha1.Vpc{}).
			WithInterceptorFuncs(funcs).
			Build()

		return &VpcReconciler{Client: c, Scheme: testScheme}, c
	}

	expectStillReady := func(c client.Client) {
		var current juneauv1alpha1.Vpc
		Expect(c.Get(ctx, client.ObjectKey{Name: defaultVpcName}, &current)).To(Succeed())

		ready := meta.FindStatusCondition(current.Status.Conditions, juneauv1alpha1.VpcStatusReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Reason).NotTo(Equal(vpcReasonReconcileFailed))
		Expect(ready.Status).To(Equal(metav1.ConditionTrue))
	}

	It("requeues without touching the status when the main RouteTable is created by someone else first", func() {
		r, c := newReconciler(
			[]client.Object{newReadyVpc()},
			interceptor.Funcs{
				Create: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if _, ok := obj.(*juneauv1alpha1.RouteTable); ok {
						return errors.NewAlreadyExists(routeTableResource, obj.GetName())
					}
					return inner.Create(ctx, obj, opts...)
				},
			},
		)

		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: defaultVpcName}})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).To(BeTrue())

		expectStillReady(c)
	})

	It("requeues without touching the status when the main RouteTable update loses the optimistic lock", func() {
		existing := &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: defaultVpcName},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: defaultVpcName},
		}

		r, c := newReconciler(
			[]client.Object{newReadyVpc(), existing},
			interceptor.Funcs{
				Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if _, ok := obj.(*juneauv1alpha1.RouteTable); ok {
						return errors.NewConflict(routeTableResource, obj.GetName(), fmt.Errorf("the object has been modified"))
					}
					return inner.Update(ctx, obj, opts...)
				},
			},
		)

		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: defaultVpcName}})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).To(BeTrue())

		expectStillReady(c)
	})

	It("reports a main RouteTable write that is not a lost race in the status", func() {
		r, c := newReconciler(
			[]client.Object{newReadyVpc()},
			interceptor.Funcs{
				Create: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if _, ok := obj.(*juneauv1alpha1.RouteTable); ok {
						return errors.NewForbidden(routeTableResource, obj.GetName(), fmt.Errorf("user cannot create resource routetables"))
					}
					return inner.Create(ctx, obj, opts...)
				},
			},
		)

		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: defaultVpcName}})
		Expect(err).To(HaveOccurred())

		var current juneauv1alpha1.Vpc
		Expect(c.Get(ctx, client.ObjectKey{Name: defaultVpcName}, &current)).To(Succeed())

		ready := meta.FindStatusCondition(current.Status.Conditions, juneauv1alpha1.VpcStatusReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal(vpcReasonReconcileFailed))
	})
})
