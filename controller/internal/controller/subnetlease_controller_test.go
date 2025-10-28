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

var _ = Describe("SubnetLease Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			leaseName   = "test-lease"
			addressName = "test-address"
			subnetName  = "test-subnet"
			ipAddress   = "10.0.1.10"
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("creating prerequisite resources")
			// Create VPC
			vpc := &juneauloutresmev1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			// Create Subnet
			subnet := &juneauloutresmev1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: subnetName,
				},
				Spec: juneauloutresmev1alpha1.SubnetSpec{
					Vpc:                "test-vpc",
					CIDR:               "10.0.1.0/24",
					AllocationStrategy: juneauloutresmev1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Create Address that will own the lease
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

			// Wait for Address to have UID and be fully synced
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: addressName, Namespace: "default"}, address)
				return err == nil && address.UID != ""
			}, "10s", "100ms").Should(BeTrue())

			// Also wait a bit for the Address to be fully registered in the cache
			// to prevent the SubnetLeaseReconciler from deleting the lease immediately
			Eventually(func() bool {
				checkAddress := &juneauloutresmev1alpha1.Address{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: addressName, Namespace: "default"}, checkAddress)
				return err == nil && checkAddress.UID == address.UID
			}, "5s", "100ms").Should(BeTrue())

			// Create SubnetLease with proper owner reference
			lease := &juneauloutresmev1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: leaseName,
				},
				Spec: juneauloutresmev1alpha1.SubnetLeaseSpec{
					Subnet: subnetName,
					IP:     ipAddress,
					Owner: juneauloutresmev1alpha1.OwnerRef{
						Namespace: address.Namespace,
						Name:      address.Name,
						UID:       string(address.UID),
					},
				},
			}
			Expect(k8sClient.Create(ctx, lease)).To(Succeed())

			// Wait for the lease to be fully created and not deleted by the reconciler
			Eventually(func() bool {
				checkLease := &juneauloutresmev1alpha1.SubnetLease{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: leaseName}, checkLease)
				return err == nil && checkLease.UID != ""
			}, "5s", "200ms").Should(BeTrue())
		})

		AfterEach(func() {
			By("cleaning up test resources")
			// Clean up SubnetLease (may already be deleted by reconciler)
			lease := &juneauloutresmev1alpha1.SubnetLease{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: leaseName}, lease); err == nil {
				k8sClient.Delete(ctx, lease)
			}
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
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-vpc"}, vpc); err == nil {
				Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
			}
		})

		It("should keep lease when owner exists", func() {
			By("reconciling the SubnetLease")
			reconciler := &SubnetLeaseReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: leaseName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the lease still exists")
			lease := &juneauloutresmev1alpha1.SubnetLease{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: leaseName}, lease)).To(Succeed())
		})

		It("should delete stale lease when owner does not exist", func() {
			By("deleting the owner Address")
			address := &juneauloutresmev1alpha1.Address{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: addressName, Namespace: "default"}, address)).To(Succeed())
			Expect(k8sClient.Delete(ctx, address)).To(Succeed())

			By("waiting for Address deletion to propagate")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: addressName, Namespace: "default"}, address)
				return errors.IsNotFound(err)
			}, "5s", "100ms").Should(BeTrue())

			By("reconciling the SubnetLease after owner deletion")
			Eventually(func() bool {
				reconciler := &SubnetLeaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				}
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: leaseName},
				})
				if err != nil {
					return false
				}

				// Check if lease was deleted
				lease := &juneauloutresmev1alpha1.SubnetLease{}
				err = k8sClient.Get(ctx, types.NamespacedName{Name: leaseName}, lease)
				return errors.IsNotFound(err)
			}, "10s", "500ms").Should(BeTrue())
		})

		It("should handle non-existent lease gracefully", func() {
			By("reconciling a non-existent lease")
			reconciler := &SubnetLeaseReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "non-existent"},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
