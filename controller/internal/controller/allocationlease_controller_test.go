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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Allocation lease", func() {
	ctx := context.Background()

	It("auto-creates a lease and inherits its value when the same claim is recreated", func() {
		releaseAfter := metav1.Duration{Duration: time.Hour}
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-lease-reuse"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 100, Max: 200},
			},
		}
		owner := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "lease-owner-reuse"}}
		makeClaim := func() *juneauv1alpha1.AllocationClaim {
			return &juneauv1alpha1.AllocationClaim{
				ObjectMeta: metav1.ObjectMeta{Name: "lease-claim-reuse"},
				Spec: juneauv1alpha1.AllocationClaimSpec{
					PoolRefs:     []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
					ResourceRef:  juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: owner.Name},
					Attribute:    "status.vni",
					ReleaseAfter: &releaseAfter,
				},
			}
		}

		Expect(k8sClient.Create(ctx, pool)).To(Succeed())
		Expect(k8sClient.Create(ctx, owner)).To(Succeed())
		claim := makeClaim()
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		DeferCleanup(func() {
			cleanupLeaseTestArtifacts(ctx, "lease-claim-reuse", owner, pool)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}

		// First reconcile: allocate + create lease.
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, claim)).To(Succeed())
			g.Expect(claim.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
		}).Should(Succeed())
		firstValue := claim.Status.Value.Number
		Expect(firstValue).NotTo(BeZero())

		var lease juneauv1alpha1.AllocationLease
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, &lease)).To(Succeed())
			g.Expect(lease.Spec.Value.Number).To(Equal(firstValue))
		}).Should(Succeed())

		// Delete the claim. With ReleaseAfter > 0 the lease must persist.
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())
		Eventually(func(g Gomega) {
			err := k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, claim)
			g.Expect(errors.IsNotFound(err)).To(BeTrue(), "claim should be fully deleted after finalizer runs")
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "lease-claim-reuse"}, &lease)).To(Succeed())
			g.Expect(lease.Spec.OwnerDeletionTimestamp).NotTo(BeNil())
		}).Should(Succeed())

		// Recreate the same-named claim — it should inherit the prior value.
		recreated := makeClaim()
		Expect(k8sClient.Create(ctx, recreated)).To(Succeed())
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: recreated.Name}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: recreated.Name}, recreated)).To(Succeed())
			g.Expect(recreated.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
			g.Expect(recreated.Status.Value.Number).To(Equal(firstValue))
		}).Should(Succeed())

		// And the lease's OwnerDeletionTimestamp must be cleared again.
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: recreated.Name}, &lease)).To(Succeed())
			g.Expect(lease.Spec.OwnerDeletionTimestamp).To(BeNil())
		}).Should(Succeed())
	})

	It("removes the lease immediately when ReleaseAfter is unset", func() {
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-lease-noretain"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 10},
			},
		}
		owner := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "lease-owner-noretain"}}
		claim := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "lease-claim-noretain"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRefs:    []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: owner.Name},
				Attribute:   "status.vni",
			},
		}

		Expect(k8sClient.Create(ctx, pool)).To(Succeed())
		Expect(k8sClient.Create(ctx, owner)).To(Succeed())
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		DeferCleanup(func() {
			cleanupLeaseTestArtifacts(ctx, claim.Name, owner, pool)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, claim)).To(Succeed())
			g.Expect(claim.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
		}).Should(Succeed())

		// Lease exists.
		var lease juneauv1alpha1.AllocationLease
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, &lease)).To(Succeed())
		}).Should(Succeed())

		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())
		Eventually(func(g Gomega) {
			err := k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, &juneauv1alpha1.AllocationClaim{})
			g.Expect(errors.IsNotFound(err)).To(BeTrue())
			err = k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, &juneauv1alpha1.AllocationLease{})
			g.Expect(errors.IsNotFound(err)).To(BeTrue(), "lease should be deleted alongside the claim when ReleaseAfter is unset")
		}).Should(Succeed())
	})

	It("reaps a lease once OwnerDeletionTimestamp + TTL elapses", func() {
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-lease-reap"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 10},
			},
		}
		Expect(k8sClient.Create(ctx, pool)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, pool)
		})

		ttl := int32(0)
		past := metav1.NewTime(time.Now().Add(-time.Minute))
		lease := &juneauv1alpha1.AllocationLease{
			ObjectMeta: metav1.ObjectMeta{Name: "lease-reap"},
			Spec: juneauv1alpha1.AllocationLeaseSpec{
				PoolRef: juneauv1alpha1.AllocationPoolReference{Name: pool.Name},
				Value:   juneauv1alpha1.AllocationValue{Number: 5},
				ReuseKey: juneauv1alpha1.AllocationResourceReference{
					APIVersion: juneauv1alpha1.GroupVersion.String(),
					Kind:       "Vpc",
					Name:       "ghost",
				},
				OwnerDeletionTimestamp: &past,
				TTLSeconds:             &ttl,
			},
		}
		Expect(k8sClient.Create(ctx, lease)).To(Succeed())

		leaseReconciler := &AllocationLeaseReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Eventually(func(g Gomega) {
			_, err := leaseReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: lease.Name}})
			g.Expect(err).NotTo(HaveOccurred())
			err = k8sClient.Get(ctx, client.ObjectKey{Name: lease.Name}, &juneauv1alpha1.AllocationLease{})
			g.Expect(errors.IsNotFound(err)).To(BeTrue(), "expired lease should be deleted")
		}).Should(Succeed())
	})

	It("reserves the value while a lease is in Released state", func() {
		releaseAfter := metav1.Duration{Duration: time.Hour}
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-lease-reserve"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeNumber,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				Number:   &juneauv1alpha1.AllocationPoolNumberSpec{Min: 1, Max: 3},
			},
		}
		ownerA := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "lease-reserve-owner-a"}}
		ownerB := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "lease-reserve-owner-b"}}
		claimA := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "lease-reserve-a"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRefs:     []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef:  juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerA.Name},
				Attribute:    "status.vni",
				ReleaseAfter: &releaseAfter,
			},
		}
		claimB := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "lease-reserve-b"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRefs:    []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerB.Name},
				Attribute:   "status.vni",
			},
		}

		Expect(k8sClient.Create(ctx, pool)).To(Succeed())
		Expect(k8sClient.Create(ctx, ownerA)).To(Succeed())
		Expect(k8sClient.Create(ctx, ownerB)).To(Succeed())
		Expect(k8sClient.Create(ctx, claimA)).To(Succeed())
		DeferCleanup(func() {
			cleanupLeaseTestArtifacts(ctx, claimA.Name, ownerA, nil)
			cleanupLeaseTestArtifacts(ctx, claimB.Name, ownerB, pool)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claimA.Name}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimA.Name}, claimA)).To(Succeed())
			g.Expect(claimA.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
		}).Should(Succeed())
		valueA := claimA.Status.Value.Number

		// Delete A; the lease for A keeps its value reserved.
		Expect(k8sClient.Delete(ctx, claimA)).To(Succeed())
		Eventually(func(g Gomega) {
			err := k8sClient.Get(ctx, client.ObjectKey{Name: claimA.Name}, &juneauv1alpha1.AllocationClaim{})
			g.Expect(errors.IsNotFound(err)).To(BeTrue())
		}).Should(Succeed())

		// B should NOT pick A's value.
		Expect(k8sClient.Create(ctx, claimB)).To(Succeed())
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claimB.Name}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimB.Name}, claimB)).To(Succeed())
			g.Expect(claimB.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
			g.Expect(claimB.Status.Value.Number).NotTo(Equal(valueA))
		}).Should(Succeed())
	})
})

// cleanupLeaseTestArtifacts best-effort deletes the claim, the lease, and
// optionally the owner / pool. It is safe to call even if the resources
// no longer exist.
func cleanupLeaseTestArtifacts(ctx context.Context, leaseName string, owner client.Object, pool *juneauv1alpha1.AllocationPool) {
	_ = k8sClient.Delete(ctx, &juneauv1alpha1.AllocationClaim{ObjectMeta: metav1.ObjectMeta{Name: leaseName}})
	// Wait for the claim's finalizer to drop the lease (or lease may still
	// exist if ReleaseAfter retained it; remove it explicitly).
	_ = k8sClient.Delete(ctx, &juneauv1alpha1.AllocationLease{ObjectMeta: metav1.ObjectMeta{Name: leaseName}})
	if owner != nil {
		_ = k8sClient.Delete(ctx, owner)
	}
	if pool != nil {
		_ = k8sClient.Delete(ctx, pool)
	}
}
