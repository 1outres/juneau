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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("SubnetLease Webhook", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("When creating SubnetLease under Validating Webhook", func() {
		It("Should admit creation with valid subnet, IP, and MAC", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-lease-valid",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-lease-valid",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-lease-valid",
					CIDR:               "10.0.0.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-lease-valid"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating lease with valid fields")
			lease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease-valid",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "test-subnet-lease-valid",
					IP:     "10.0.0.100",
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, lease)
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with non-existent subnet", func() {
			lease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease-nosubnet",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "non-existent-subnet",
					IP:     "10.0.0.10",
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, lease)
			Expect(err).To(HaveOccurred())
			// The error can be either "referenced Subnet does not exist" or "invalid CIDR format"
			// depending on whether Get returns NotFound or an empty object
			Expect(err.Error()).To(Or(
				ContainSubstring("referenced Subnet does not exist"),
				ContainSubstring("invalid CIDR format"),
			))
		})

		It("Should deny creation with invalid IP format", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-lease-badip",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-lease-badip",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-lease-badip",
					CIDR:               "10.0.1.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-lease-badip"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating lease with invalid IP")
			lease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease-badip",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "test-subnet-lease-badip",
					IP:     "not-an-ip",
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, lease)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("IP address is not valid or not in the referenced Subnet CIDR range"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with IP outside subnet CIDR", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-lease-ipout",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-lease-ipout",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-lease-ipout",
					CIDR:               "192.168.1.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-lease-ipout"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating lease with IP outside subnet CIDR")
			lease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease-ipout",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "test-subnet-lease-ipout",
					IP:     "192.168.2.100", // Outside 192.168.1.0/24
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, lease)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("IP address is not valid or not in the referenced Subnet CIDR range"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with invalid MAC format", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-lease-badmac",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-lease-badmac",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-lease-badmac",
					CIDR:               "10.0.2.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-lease-badmac"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating lease with invalid MAC")
			lease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease-badmac",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "test-subnet-lease-badmac",
					IP:     "10.0.2.100",
					MAC:    "invalid-mac-address",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, lease)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid MAC address format"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})
	})

	Context("When updating SubnetLease under Validating Webhook", func() {
		It("Should admit update with no spec changes", func() {
			oldLease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "test-subnet",
					IP:     "10.0.0.10",
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			newLease := oldLease.DeepCopy()

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldLease, newLease)
			Expect(err).NotTo(HaveOccurred())
		})

		It("Should deny update when subnet changes", func() {
			oldLease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "old-subnet",
					IP:     "10.0.0.10",
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			newLease := oldLease.DeepCopy()
			newLease.Spec.Subnet = "new-subnet"

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldLease, newLease)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("field is immutable"))
		})

		It("Should deny update when IP changes", func() {
			oldLease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "test-subnet",
					IP:     "10.0.0.10",
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			newLease := oldLease.DeepCopy()
			newLease.Spec.IP = "10.0.0.20"

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldLease, newLease)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("field is immutable"))
		})

		It("Should deny update when MAC changes", func() {
			oldLease := &juneauv1alpha1.SubnetLease{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-lease",
				},
				Spec: juneauv1alpha1.SubnetLeaseSpec{
					Subnet: "test-subnet",
					IP:     "10.0.0.10",
					MAC:    "00:11:22:33:44:55",
					Owner: juneauv1alpha1.OwnerRef{
						Namespace: "default",
						Name:      "test-owner",
						UID:       "test-uid",
					},
				},
			}

			newLease := oldLease.DeepCopy()
			newLease.Spec.MAC = "aa:bb:cc:dd:ee:ff"

			validator := &SubnetLeaseCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldLease, newLease)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("field is immutable"))
		})
	})
})
