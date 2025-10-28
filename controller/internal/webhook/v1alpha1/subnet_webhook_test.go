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

var _ = Describe("Subnet Webhook", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("When creating Subnet under Defaulting Webhook", func() {
		It("Should normalize CIDR format", func() {
			By("creating a subnet with non-normalized CIDR")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-normalize",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc",
					CIDR:               "10.0.1.0/24", // Should be normalized
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			defaulter := &SubnetCustomDefaulter{}
			err := defaulter.Default(ctx, subnet)
			Expect(err).NotTo(HaveOccurred())
			Expect(subnet.Spec.CIDR).To(Equal("10.0.1.0/24"))
		})

		It("Should return error for invalid CIDR", func() {
			By("creating a subnet with invalid CIDR")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-invalid",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc",
					CIDR:               "invalid-cidr",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			defaulter := &SubnetCustomDefaulter{}
			err := defaulter.Default(ctx, subnet)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("When creating Subnet under Validating Webhook", func() {
		It("Should admit creation with valid CIDR and existing VPC", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-valid",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating subnet with valid CIDR")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-valid",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-valid",
					CIDR:               "192.168.1.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, subnet)
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with invalid CIDR format", func() {
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-invalid-cidr",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc",
					CIDR:               "not-a-cidr",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, subnet)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid CIDR format"))
		})

		It("Should deny creation with CIDR prefix length < 16", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-prefix-small",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating subnet with /15 CIDR")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-prefix-small",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-prefix-small",
					CIDR:               "10.0.0.0/15",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, subnet)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("prefix length must be between 16 and 28"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with CIDR prefix length > 28", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-prefix-large",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating subnet with /29 CIDR")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-prefix-large",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-prefix-large",
					CIDR:               "10.0.0.0/29",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, subnet)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("prefix length must be between 16 and 28"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny creation with non-existent VPC", func() {
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-novpc",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "non-existent-vpc",
					CIDR:               "10.0.0.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, subnet)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
		})

		It("Should deny creation with overlapping CIDR", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-overlap",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating first subnet")
			subnet1 := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-overlap-1",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-overlap",
					CIDR:               "10.0.0.0/16",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet1)).To(Succeed())

			// Wait for subnet1 to be synced in cache
			Eventually(func() error {
				var s juneauv1alpha1.Subnet
				return k8sClient.Get(ctx, client.ObjectKey{Name: "test-subnet-overlap-1"}, &s)
			}, "5s", "100ms").Should(Succeed())

			By("creating second subnet with overlapping CIDR")
			subnet2 := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-overlap-2",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-overlap",
					CIDR:               "10.0.1.0/24", // Overlaps with 10.0.0.0/16
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateCreate(ctx, subnet2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("overlaps with existing subnets"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet1)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})
	})

	Context("When updating Subnet under Validating Webhook", func() {
		It("Should admit update with no spec changes", func() {
			By("creating prerequisite VPC")
			vpc := &juneauv1alpha1.Vpc{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vpc-update",
				},
			}
			Expect(k8sClient.Create(ctx, vpc)).To(Succeed())

			By("creating subnet")
			subnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet-update",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc-update",
					CIDR:               "10.0.0.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())

			By("updating subnet without changing immutable fields")
			updatedSubnet := subnet.DeepCopy()

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, subnet, updatedSubnet)
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			Expect(k8sClient.Delete(ctx, subnet)).To(Succeed())
			Expect(k8sClient.Delete(ctx, vpc)).To(Succeed())
		})

		It("Should deny update when VPC changes", func() {
			oldSubnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "old-vpc",
					CIDR:               "10.0.0.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			newSubnet := oldSubnet.DeepCopy()
			newSubnet.Spec.Vpc = "new-vpc"

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldSubnet, newSubnet)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("changing the Vpc of a Subnet is not allowed"))
		})

		It("Should deny update when CIDR changes", func() {
			oldSubnet := &juneauv1alpha1.Subnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-subnet",
				},
				Spec: juneauv1alpha1.SubnetSpec{
					Vpc:                "test-vpc",
					CIDR:               "10.0.0.0/24",
					AllocationStrategy: juneauv1alpha1.SubnetAllocationStrategyFirstFit,
				},
			}

			newSubnet := oldSubnet.DeepCopy()
			newSubnet.Spec.CIDR = "10.0.1.0/24"

			validator := &SubnetCustomValidator{Client: k8sClient}
			_, err := validator.ValidateUpdate(ctx, oldSubnet, newSubnet)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("changing the CIDR of a Subnet is not allowed"))
		})
	})
})
