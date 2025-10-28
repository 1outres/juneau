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

var _ = Describe("Address Webhook", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("When creating Address under Validating Webhook", func() {
		It("Should admit creation with valid subnet", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-addr-valid",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-addr-valid",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-addr-valid",
					CIDR:               "10.0.0.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-addr-valid"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating address with valid subnet")
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-valid",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet: "test-subnet-addr-valid",
					MAC:    "00:11:22:33:44:55",
				},
			}

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, address)
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with non-existent subnet", func() {
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-nosubnet",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet: "non-existent-subnet",
				},
			}

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, address)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("referenced Subnet does not exist"))
		})

		It("Should admit creation with valid MAC address", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-addr-mac",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-addr-mac",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-addr-mac",
					CIDR:               "10.0.1.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-addr-mac"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating address with valid MAC")
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-mac",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet: "test-subnet-addr-mac",
					MAC:    "00:11:22:33:44:55",
				},
			}

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, address)
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with invalid MAC address format", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-addr-badmac",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-addr-badmac",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-addr-badmac",
					CIDR:               "10.0.2.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-addr-badmac"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating address with invalid MAC")
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-badmac",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet: "test-subnet-addr-badmac",
					MAC:    "invalid-mac",
				},
			}

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, address)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid MAC address format"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should admit creation with IP address in subnet CIDR", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-addr-ip",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-addr-ip",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-addr-ip",
					CIDR:               "192.168.1.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-addr-ip"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating address with IP in subnet CIDR")
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-ip",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet:  "test-subnet-addr-ip",
					MAC:     "00:11:22:33:44:55",
					Address: "192.168.1.100",
				},
			}

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, address)
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with IP address outside subnet CIDR", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-addr-badip",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-addr-badip",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-addr-badip",
					CIDR:               "192.168.1.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-addr-badip"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating address with IP outside subnet CIDR")
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-badip",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet:  "test-subnet-addr-badip",
					MAC:     "00:11:22:33:44:55",
					Address: "192.168.2.100", // Outside 192.168.1.0/24
				},
			}

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, address)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("is not within the specified Subnet CIDR"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with invalid IP address format", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-addr-invalidip",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-addr-invalidip",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-addr-invalidip",
					CIDR:               "192.168.3.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-addr-invalidip"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating address with invalid IP format")
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-invalidip",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet:  "test-subnet-addr-invalidip",
					Address: "not-an-ip-address",
				},
			}

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, address)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid IP address format"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})
	})

	Context("When updating Address under Validating Webhook", func() {
		It("Should admit update with no spec changes", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-addr-update",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating prerequisite Subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-addr-update",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-addr-update",
					CIDR:               "10.0.3.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			// Wait for subnet to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-addr-update"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating address")
			address := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address-update",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet: "test-subnet-addr-update",
					MAC:    "00:11:22:33:44:55",
				},
			}
			Expect(k8sClient.Create(ctx, address)).To(Succeed())

			By("updating address without changing immutable fields")
			updatedAddress := address.DeepCopy()

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, address, updatedAddress)
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			Expect(k8sClient.Delete(ctx, address)).To(Succeed())
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny update when subnet changes", func() {
			oldAddress := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet: "old-subnet",
				},
			}

			newAddress := oldAddress.DeepCopy()
			newAddress.Spec.Subnet = "new-subnet"

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldAddress, newAddress)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("field is immutable"))
		})

		It("Should deny update when MAC address changes", func() {
			oldAddress := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet: "test-subnet",
					MAC:    "00:11:22:33:44:55",
				},
			}

			newAddress := oldAddress.DeepCopy()
			newAddress.Spec.MAC = "aa:bb:cc:dd:ee:ff"

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldAddress, newAddress)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("field is immutable"))
		})

		It("Should deny update when IP address changes", func() {
			oldAddress := &juneauv1alpha1.Address{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-address",
					Namespace: "default",
				},
				Spec: juneauv1alpha1.AddressSpec{
					Subnet:  "test-subnet",
					Address: "10.0.0.10",
				},
			}

			newAddress := oldAddress.DeepCopy()
			newAddress.Spec.Address = "10.0.0.20"

			validator := &AddressCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldAddress, newAddress)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("field is immutable"))
		})
	})
})
