package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Allocation webhooks", func() {
	ctx := context.Background()

	Describe("AllocationPool", func() {
		It("defaults type and strategy", func() {
			obj := &juneauv1alpha1.AllocationPool{}
			Expect((&AllocationPoolCustomDefaulter{}).Default(ctx, obj)).To(Succeed())
			Expect(obj.Spec.Type).To(Equal(juneauv1alpha1.AllocationTypeNumber))
			Expect(obj.Spec.Strategy).To(Equal(juneauv1alpha1.AllocationStrategyFirstFit))
		})

		It("accepts type=number with a valid number range", func() {
			Expect(webhookK8sClient.Create(ctx, &juneauv1alpha1.AllocationPool{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationpool")},
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
					Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 10},
				},
			})).To(Succeed())
		})

		It("rejects type=number without spec.number", func() {
			err := webhookK8sClient.Create(ctx, &juneauv1alpha1.AllocationPool{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationpool")},
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.number"))
		})

		It("rejects an invalid number range where min > max", func() {
			err := webhookK8sClient.Create(ctx, &juneauv1alpha1.AllocationPool{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationpool")},
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
					Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 10, Max: 2},
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be less than or equal"))
		})

		It("rejects immutable spec.type update", func() {
			pool := &juneauv1alpha1.AllocationPool{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationpool")},
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
					Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 10},
				},
			}
			Expect(webhookK8sClient.Create(ctx, pool)).To(Succeed())

			var current juneauv1alpha1.AllocationPool
			Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(pool), &current)).To(Succeed())
			current.Spec.Type = juneauv1alpha1.AllocationTypeIP
			err := webhookK8sClient.Update(ctx, &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.type is immutable"))
		})

		It("rejects immutable spec.number.min/max updates", func() {
			pool := &juneauv1alpha1.AllocationPool{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationpool")},
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
					Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 10},
				},
			}
			Expect(webhookK8sClient.Create(ctx, pool)).To(Succeed())

			var current juneauv1alpha1.AllocationPool
			Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(pool), &current)).To(Succeed())
			current.Spec.Number.Min = 2
			err := webhookK8sClient.Update(ctx, &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.number.min is immutable"))

			Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(pool), &current)).To(Succeed())
			current.Spec.Number.Max = 20
			err = webhookK8sClient.Update(ctx, &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.number.max is immutable"))
		})

		It("rejects deletion while an AllocationClaim references the pool", func() {
			pool := &juneauv1alpha1.AllocationPool{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationpool")},
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
					Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 10},
				},
			}
			Expect(webhookK8sClient.Create(ctx, pool)).To(Succeed())

			claim := &juneauv1alpha1.AllocationClaim{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationclaim")},
				Spec: juneauv1alpha1.AllocationClaimSpec{
					PoolRef:     juneauv1alpha1.AllocationPoolReference{Name: pool.Name},
					ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: "does-not-matter"},
					Attribute:   "status.vni",
				},
			}
			Expect(webhookK8sClient.Create(ctx, claim)).To(Succeed())

			err := webhookK8sClient.Delete(ctx, pool)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("is referenced by AllocationClaim"))
		})

		It("allows deletion when nothing references the pool", func() {
			pool := &juneauv1alpha1.AllocationPool{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationpool")},
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
					Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 10},
				},
			}
			Expect(webhookK8sClient.Create(ctx, pool)).To(Succeed())
			Expect(webhookK8sClient.Delete(ctx, pool)).To(Succeed())
		})
	})

	Describe("AllocationClaim", func() {
		It("rejects missing required fields via markers", func() {
			err := webhookK8sClient.Create(ctx, &juneauv1alpha1.AllocationClaim{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationclaim")},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.poolRef"))
			Expect(err.Error()).To(ContainSubstring("spec.resourceRef"))
			Expect(err.Error()).To(ContainSubstring("spec.attribute"))
		})

		It("rejects empty spec.poolRef.name", func() {
			err := webhookK8sClient.Create(ctx, &juneauv1alpha1.AllocationClaim{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationclaim")},
				Spec: juneauv1alpha1.AllocationClaimSpec{
					PoolRef:     juneauv1alpha1.AllocationPoolReference{Name: ""},
					ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: "owner"},
					Attribute:   "status.vni",
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.poolRef.name"))
		})

		It("rejects empty spec.attribute", func() {
			err := webhookK8sClient.Create(ctx, &juneauv1alpha1.AllocationClaim{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationclaim")},
				Spec: juneauv1alpha1.AllocationClaimSpec{
					PoolRef:     juneauv1alpha1.AllocationPoolReference{Name: "subnet-vni"},
					ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: "owner"},
					Attribute:   "",
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.attribute"))
		})

		It("rejects spec.requestedNumber=0 via minimum marker", func() {
			zero := uint64(0)
			err := webhookK8sClient.Create(ctx, &juneauv1alpha1.AllocationClaim{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationclaim")},
				Spec: juneauv1alpha1.AllocationClaimSpec{
					PoolRef:         juneauv1alpha1.AllocationPoolReference{Name: "subnet-vni"},
					ResourceRef:     juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: "owner"},
					Attribute:       "status.vni",
					RequestedNumber: &zero,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.requestedNumber"))
		})

		It("treats core spec fields as immutable", func() {
			oldRequested := uint64(2)
			newRequested := uint64(3)
			oldObj := &juneauv1alpha1.AllocationClaim{
				Spec: juneauv1alpha1.AllocationClaimSpec{
					PoolRef:         juneauv1alpha1.AllocationPoolReference{Name: "subnet-vni"},
					ResourceRef:     juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Subnet", Name: "s1"},
					Attribute:       "status.vni",
					RequestedNumber: &oldRequested,
				},
			}
			newObj := oldObj.DeepCopy()
			newObj.Spec.RequestedNumber = &newRequested
			_, err := (&AllocationClaimCustomValidator{}).ValidateUpdate(ctx, oldObj, newObj)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.requestedNumber is immutable"))
		})

		It("rejects immutable spec.poolRef.name update via envtest", func() {
			requested := uint64(5)
			claim := &juneauv1alpha1.AllocationClaim{
				ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("allocationclaim")},
				Spec: juneauv1alpha1.AllocationClaimSpec{
					PoolRef:         juneauv1alpha1.AllocationPoolReference{Name: "subnet-vni"},
					ResourceRef:     juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: "owner"},
					Attribute:       "status.vni",
					RequestedNumber: &requested,
				},
			}
			Expect(webhookK8sClient.Create(ctx, claim)).To(Succeed())

			var current juneauv1alpha1.AllocationClaim
			Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(claim), &current)).To(Succeed())
			current.Spec.PoolRef.Name = "route-table-id"
			err := webhookK8sClient.Update(ctx, &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.poolRef.name is immutable"))

			Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(claim), &current)).To(Succeed())
			current.Spec.Attribute = "status.other"
			err = webhookK8sClient.Update(ctx, &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.attribute is immutable"))

			Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(claim), &current)).To(Succeed())
			current.Spec.ResourceRef.Name = "other"
			err = webhookK8sClient.Update(ctx, &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.resourceRef is immutable"))
		})
	})
})
