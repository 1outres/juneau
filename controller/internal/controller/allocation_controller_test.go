package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Allocation controllers", func() {
	ctx := context.Background()

	It("allocates distinct numbers for claims in the same pool", func() {
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-distinct"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 2, Max: 10},
			},
		}
		ownerA := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "claim-owner-a"}}
		ownerB := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "claim-owner-b"}}
		claimA := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "claim-a"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRef:     juneauv1alpha1.AllocationPoolReference{Name: pool.Name},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerA.Name},
				Attribute:   "status.vni",
			},
		}
		claimB := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "claim-b"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRef:     juneauv1alpha1.AllocationPoolReference{Name: pool.Name},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerB.Name},
				Attribute:   "status.vni",
			},
		}

		Expect(k8sClient.Create(ctx, pool)).To(Succeed())
		Expect(k8sClient.Create(ctx, ownerA)).To(Succeed())
		Expect(k8sClient.Create(ctx, ownerB)).To(Succeed())
		Expect(k8sClient.Create(ctx, claimA)).To(Succeed())
		Expect(k8sClient.Create(ctx, claimB)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, claimA)
			_ = k8sClient.Delete(ctx, claimB)
			_ = k8sClient.Delete(ctx, ownerA)
			_ = k8sClient.Delete(ctx, ownerB)
			_ = k8sClient.Delete(ctx, pool)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claimA.Name}})
		Expect(err).NotTo(HaveOccurred())
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claimB.Name}})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimA.Name}, claimA)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimB.Name}, claimB)).To(Succeed())
		Expect(claimA.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
		Expect(claimB.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
		Expect(claimA.Status.Value.Number).To(Equal(uint64(2)))
		Expect(claimB.Status.Value.Number).To(Equal(uint64(3)))
	})

	It("honors a requested number when available", func() {
		requested := uint64(9)
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-requested"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 2, Max: 10},
			},
		}
		owner := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "claim-owner-requested"}}
		claim := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "claim-requested"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRef:         juneauv1alpha1.AllocationPoolReference{Name: pool.Name},
				ResourceRef:     juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: owner.Name},
				Attribute:       "status.vni",
				RequestedNumber: &requested,
			},
		}

		Expect(k8sClient.Create(ctx, pool)).To(Succeed())
		Expect(k8sClient.Create(ctx, owner)).To(Succeed())
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, claim)
			_ = k8sClient.Delete(ctx, owner)
			_ = k8sClient.Delete(ctx, pool)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name}})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, claim)).To(Succeed())
		Expect(claim.Status.Value.Number).To(Equal(requested))
	})
})
