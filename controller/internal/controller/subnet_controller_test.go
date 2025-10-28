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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Subnet Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			subnetName = "test-subnet"
			vpcName    = "test-vpc"
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("creating a VPC for the subnet")
			vpc := &juneauloutresmev1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: vpcName,
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up test resources")
			// Clean up subnet
			subnet := &juneauloutresmev1alpha1.Subnet{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: subnetName}, subnet); err == nil {
				Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			}
			// Clean up VPC
			vpc := &juneauloutresmev1alpha1.Vpc{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: vpcName}, vpc); err == nil {
				Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
			}
		})

		It("should calculate subnet status correctly", func() {
			By("creating a subnet with /24 CIDR")
			subnet := &juneauloutresmev1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: subnetName,
				},
				Spec: juneauloutresmev1alpha1.SubnetSpec{
					Vpc:                vpcName,
					CIDR:               "192.168.1.0/24",
					AllocationStrategy: juneauloutresmev1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			By("reconciling the subnet and verifying status")
			Eventually(func() bool {
				reconciler := &SubnetReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				}
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: subnetName},
				})
				if err != nil {
					return false
				}

				// Check if status was updated
				updatedSubnet := &juneauloutresmev1alpha1.Subnet{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: subnetName}, updatedSubnet); err != nil {
					return false
				}
				return updatedSubnet.Status.Gateway == "192.168.1.1" &&
					updatedSubnet.Status.Capacity == uint64(254) &&
					updatedSubnet.Status.Used == uint64(0) &&
					updatedSubnet.Status.NextCursor == "192.168.1.5"
			}, "10s", "500ms").Should(BeTrue())
		})

		It("should handle subnet not found gracefully", func() {
			By("reconciling a non-existent subnet")
			reconciler := &SubnetReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "non-existent"},
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle deletion timestamp", func() {
			By("creating a subnet")
			subnet := &juneauloutresmev1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: subnetName,
				},
				Spec: juneauloutresmev1alpha1.SubnetSpec{
					Vpc:                vpcName,
					CIDR:               "192.168.2.0/24",
					AllocationStrategy: juneauloutresmev1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			By("reconciling the subnet before deletion")
			reconciler := &SubnetReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: subnetName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("marking subnet for deletion")
			// Get the latest version before deletion
			err = k8sClient.Get(ctx, types.NamespacedName{Name: subnetName}, subnet)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())

			By("verifying reconciliation with deletion timestamp")
			// The controller should either:
			// 1. Return early (no error) if object still exists with DeletionTimestamp
			// 2. Return no error if object is already gone (NotFound)
			// 3. Return a conflict error if trying to update a deleted object
			// All of these are acceptable for a deleted object
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: subnetName},
			})
			// We accept either no error or a conflict error
			if err != nil {
				Expect(errors.IsConflict(err) || errors.IsNotFound(err)).To(BeTrue(),
					"Expected no error, NotFound, or Conflict, but got: %v", err)
			}
		})
	})
})
