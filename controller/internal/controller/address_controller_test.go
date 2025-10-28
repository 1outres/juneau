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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Address Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			addressName = "test-address"
			subnetName  = "test-subnet"
			vpcName     = "test-vpc"
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("creating prerequisite resources")
			// Create VPC
			vpc := &juneauloutresmev1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: vpcName,
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			// Create Subnet
			subnet := &juneauloutresmev1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: subnetName,
				},
				Spec: juneauloutresmev1alpha1.SubnetSpec{
					Vpc:                vpcName,
					CIDR:               "10.0.0.0/24",
					AllocationStrategy: juneauloutresmev1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Reconcile the Subnet to populate its status
			By("reconciling the Subnet to populate status")
			Eventually(func() bool {
				subnetReconciler := &SubnetReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				}
				_, err := subnetReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: subnetName},
				})
				if err != nil {
					return false
				}

				// Check if status was populated
				updatedSubnet := &juneauloutresmev1alpha1.Subnet{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: subnetName}, updatedSubnet); err != nil {
					return false
				}
				return updatedSubnet.Status.Gateway != "" && updatedSubnet.Status.NextCursor != ""
			}, "10s", "500ms").Should(BeTrue())
		})

		AfterEach(func() {
			By("cleaning up test resources")
			// Clean up Address
			address := &juneauloutresmev1alpha1.Address{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: addressName, Namespace: "default"}, address); err == nil {
				Expect(k8sClient.Delete(ctx, address)).To(Succeed())
			}
			// Clean up Subnet
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

		It("should allocate an IP address from the subnet", func() {
			By("creating an Address resource")
			address := &juneauloutresmev1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      addressName,
					Namespace: "default",
				},
				Spec: juneauloutresmev1alpha1.AddressSpec{
					Subnet: subnetName,
				},
			}
			Expect(k8sClient.Create(ctx, address)).To(Succeed())

			By("reconciling the Address")
			reconciler := &AddressReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: addressName, Namespace: "default"},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying an IP address was allocated")
			Eventually(func() bool {
				// Re-reconcile to ensure status gets updated
				reconciler := &AddressReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				}
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: addressName, Namespace: "default"},
				})
				if err != nil {
					return false
				}

				updatedAddress := &juneauloutresmev1alpha1.Address{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: addressName, Namespace: "default"}, updatedAddress); err != nil {
					return false
				}
				return updatedAddress.Status.Address != "" && updatedAddress.Status.LeaseName != ""
			}, "15s", "1s").Should(BeTrue())
		})

		It("should handle non-existent address gracefully", func() {
			By("reconciling a non-existent address")
			reconciler := &AddressReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "non-existent", Namespace: "default"},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
