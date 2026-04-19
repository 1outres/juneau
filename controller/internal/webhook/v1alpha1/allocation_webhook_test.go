package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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

		It("rejects an invalid number range", func() {
			obj := &juneauv1alpha1.AllocationPool{
				Spec: juneauv1alpha1.AllocationPoolSpec{
					Type:     juneauv1alpha1.AllocationTypeNumber,
					Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
					Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 10, Max: 2},
				},
			}
			_, err := (&AllocationPoolCustomValidator{}).ValidateCreate(ctx, obj)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("AllocationClaim", func() {
		It("requires pool and resource references", func() {
			obj := &juneauv1alpha1.AllocationClaim{}
			_, err := (&AllocationClaimCustomValidator{}).ValidateCreate(ctx, obj)
			Expect(err).To(HaveOccurred())
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
		})
	})
})
