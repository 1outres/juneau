package controller

import (
	"context"
	"fmt"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
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
				PoolRefs:    []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerA.Name},
				Attribute:   "status.vni",
			},
		}
		claimB := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "claim-b"},
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
		Expect(k8sClient.Create(ctx, claimB)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, claimA)
			_ = k8sClient.Delete(ctx, claimB)
			_ = k8sClient.Delete(ctx, ownerA)
			_ = k8sClient.Delete(ctx, ownerB)
			_ = k8sClient.Delete(ctx, pool)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
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
		Expect(meta.FindStatusCondition(claimA.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)).NotTo(BeNil())
		Expect(meta.FindStatusCondition(claimA.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady).ObservedGeneration).To(Equal(claimA.Generation))
		Expect(meta.FindStatusCondition(claimB.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)).NotTo(BeNil())
		Expect(meta.FindStatusCondition(claimB.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady).ObservedGeneration).To(Equal(claimB.Generation))
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
				PoolRefs:        []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
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

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name}})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, claim)).To(Succeed())
		Expect(claim.Status.Value.Number).To(Equal(requested))
		Expect(meta.FindStatusCondition(claim.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)).NotTo(BeNil())
		Expect(meta.FindStatusCondition(claim.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady).ObservedGeneration).To(Equal(claim.Generation))
	})

	It("allocates unique VNIs and route table IDs under concurrent VPC and subnet creation", func() {
		const vpcCount = 20

		vpcNames := make([]string, 0, vpcCount)
		subnetNames := make([]string, 0, vpcCount*2)

		for i := 0; i < vpcCount; i++ {
			vpcName := uniqueTestName(fmt.Sprintf("alloc-vpc-%02d", i))
			vpcNames = append(vpcNames, vpcName)
			subnetNames = append(subnetNames, uniqueTestName(fmt.Sprintf("alloc-subnet-a-%02d", i)))
			subnetNames = append(subnetNames, uniqueTestName(fmt.Sprintf("alloc-subnet-b-%02d", i)))
		}

		DeferCleanup(func() {
			for _, subnetName := range subnetNames {
				_ = k8sClient.Delete(ctx, &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: subnetName}})
			}
			for _, vpcName := range vpcNames {
				_ = k8sClient.Delete(ctx, &juneauv1alpha1.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: vpcName}})
				_ = k8sClient.Delete(ctx, &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: vpcName}})
			}
		})

		var wg sync.WaitGroup
		var mu sync.Mutex
		var createErrs []error

		for i, vpcName := range vpcNames {
			subnetA := subnetNames[i*2]
			subnetB := subnetNames[i*2+1]
			cidrBase := 20 + i*2

			wg.Add(1)
			go func(vpcName, subnetA, subnetB string, cidrBase int) {
				defer GinkgoRecover()
				defer wg.Done()

				resources := []client.Object{
					&juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: vpcName}},
					&juneauv1alpha1.Subnet{
						ObjectMeta: metav1.ObjectMeta{Name: subnetA},
						Spec:       juneauv1alpha1.SubnetSpec{Vpc: vpcName, CIDR: fmt.Sprintf("10.%d.0.0/24", cidrBase)},
					},
					&juneauv1alpha1.Subnet{
						ObjectMeta: metav1.ObjectMeta{Name: subnetB},
						Spec:       juneauv1alpha1.SubnetSpec{Vpc: vpcName, CIDR: fmt.Sprintf("10.%d.0.0/24", cidrBase+1)},
					},
				}

				for _, resource := range resources {
					if err := k8sClient.Create(ctx, resource); err != nil {
						mu.Lock()
						createErrs = append(createErrs, err)
						mu.Unlock()
					}
				}
			}(vpcName, subnetA, subnetB, cidrBase)
		}

		wg.Wait()
		Expect(createErrs).To(BeEmpty())

		Eventually(func(g Gomega) {
			var subnets juneauv1alpha1.SubnetList
			g.Expect(k8sClient.List(ctx, &subnets)).To(Succeed())

			vniOwners := map[uint32]string{}
			readySubnets := 0
			for _, subnetName := range subnetNames {
				var found *juneauv1alpha1.Subnet
				for i := range subnets.Items {
					if subnets.Items[i].Name == subnetName {
						found = &subnets.Items[i]
						break
					}
				}
				g.Expect(found).NotTo(BeNil(), "missing subnet %s", subnetName)
				ready := meta.FindStatusCondition(found.Status.Conditions, juneauv1alpha1.SubnetStatusReady)
				g.Expect(ready).NotTo(BeNil(), "missing Ready condition for subnet %s", subnetName)
				g.Expect(ready.Status).To(Equal(metav1.ConditionTrue), "subnet %s not ready", subnetName)
				g.Expect(found.Status.VNI).NotTo(BeZero(), "subnet %s missing VNI", subnetName)
				if owner, exists := vniOwners[found.Status.VNI]; exists {
					g.Expect(found.Name).To(Equal(owner), "duplicate VNI %d for subnets %s and %s", found.Status.VNI, owner, found.Name)
				} else {
					vniOwners[found.Status.VNI] = found.Name
				}
				readySubnets++
			}
			g.Expect(readySubnets).To(Equal(len(subnetNames)))

			var routeTables juneauv1alpha1.RouteTableList
			g.Expect(k8sClient.List(ctx, &routeTables)).To(Succeed())

			tableOwners := map[uint32]string{}
			readyTables := 0
			for _, vpcName := range vpcNames {
				var found *juneauv1alpha1.RouteTable
				for i := range routeTables.Items {
					if routeTables.Items[i].Name == vpcName {
						found = &routeTables.Items[i]
						break
					}
				}
				g.Expect(found).NotTo(BeNil(), "missing route table %s", vpcName)
				ready := meta.FindStatusCondition(found.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil(), "missing Ready condition for route table %s", vpcName)
				g.Expect(ready.Status).To(Equal(metav1.ConditionTrue), "route table %s not ready", vpcName)
				g.Expect(found.Status.TableID).NotTo(BeZero(), "route table %s missing tableID", vpcName)
				if owner, exists := tableOwners[found.Status.TableID]; exists {
					g.Expect(found.Name).To(Equal(owner), "duplicate tableID %d for route tables %s and %s", found.Status.TableID, owner, found.Name)
				} else {
					tableOwners[found.Status.TableID] = found.Name
				}
				readyTables++
			}
			g.Expect(readyTables).To(Equal(len(vpcNames)))
		}).Should(Succeed())
	})

	It("allocates distinct IPs from an ip-typed pool", func() {
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-ip-distinct"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeIP,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				IP: &juneauv1alpha1.AllocationPoolIPSpec{
					CIDRs: []string{"192.0.2.0/29"},
				},
			},
		}
		ownerA := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "ip-owner-a"}}
		ownerB := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "ip-owner-b"}}
		claimA := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "ip-claim-a"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRefs:    []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerA.Name},
				Attribute:   "status.address",
			},
		}
		claimB := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "ip-claim-b"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRefs:    []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerB.Name},
				Attribute:   "status.address",
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

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claimA.Name}})
		Expect(err).NotTo(HaveOccurred())
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claimB.Name}})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimA.Name}, claimA)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimB.Name}, claimB)).To(Succeed())
		Expect(claimA.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
		Expect(claimB.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
		// /29 with first usable starting at .1, broadcast at .7 → .1 then .2
		Expect(claimA.Status.Value.IP).To(Equal("192.0.2.1"))
		Expect(claimB.Status.Value.IP).To(Equal("192.0.2.2"))
	})

	It("honors a requested IP when available and respects excluded entries", func() {
		requested := "192.0.2.10"
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-ip-requested"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeIP,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				IP: &juneauv1alpha1.AllocationPoolIPSpec{
					CIDRs:    []string{"192.0.2.0/24"},
					Excluded: []string{"192.0.2.1", "192.0.2.2"},
				},
			},
		}
		owner := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "ip-owner-requested"}}
		claim := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "ip-claim-requested"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRefs:    []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: owner.Name},
				Attribute:   "status.address",
				RequestedIP: &requested,
			},
		}
		ownerB := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "ip-owner-firstfree"}}
		claimB := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "ip-claim-firstfree"},
			Spec: juneauv1alpha1.AllocationClaimSpec{
				PoolRefs:    []juneauv1alpha1.AllocationPoolReference{{Name: pool.Name}},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: ownerB.Name},
				Attribute:   "status.address",
			},
		}

		Expect(k8sClient.Create(ctx, pool)).To(Succeed())
		Expect(k8sClient.Create(ctx, owner)).To(Succeed())
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		Expect(k8sClient.Create(ctx, ownerB)).To(Succeed())
		Expect(k8sClient.Create(ctx, claimB)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, claim)
			_ = k8sClient.Delete(ctx, claimB)
			_ = k8sClient.Delete(ctx, owner)
			_ = k8sClient.Delete(ctx, ownerB)
			_ = k8sClient.Delete(ctx, pool)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name}})
		Expect(err).NotTo(HaveOccurred())
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claimB.Name}})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claim.Name}, claim)).To(Succeed())
		Expect(claim.Status.Value.IP).To(Equal(requested))
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimB.Name}, claimB)).To(Succeed())
		// Excluded skips .1 and .2, so the first-fit address is .3
		Expect(claimB.Status.Value.IP).To(Equal("192.0.2.3"))
	})

	It("falls through to the next pool when the first is exhausted", func() {
		poolA := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-ip-fallthrough-a"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeIP,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				IP: &juneauv1alpha1.AllocationPoolIPSpec{
					CIDRs: []string{"192.0.2.0/30"}, // only .1, .2 are usable
				},
			},
		}
		poolB := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-ip-fallthrough-b"},
			Spec: juneauv1alpha1.AllocationPoolSpec{
				Type:     juneauv1alpha1.AllocationTypeIP,
				Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
				IP: &juneauv1alpha1.AllocationPoolIPSpec{
					CIDRs: []string{"198.51.100.0/30"},
				},
			},
		}
		owners := []*juneauv1alpha1.Vpc{
			{ObjectMeta: metav1.ObjectMeta{Name: "ipft-owner-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "ipft-owner-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "ipft-owner-3"}},
		}
		claims := []*juneauv1alpha1.AllocationClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: "ipft-claim-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "ipft-claim-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "ipft-claim-3"}},
		}
		for i, c := range claims {
			c.Spec = juneauv1alpha1.AllocationClaimSpec{
				PoolRefs: []juneauv1alpha1.AllocationPoolReference{
					{Name: poolA.Name},
					{Name: poolB.Name},
				},
				ResourceRef: juneauv1alpha1.AllocationResourceReference{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "Vpc", Name: owners[i].Name},
				Attribute:   "status.address",
			}
		}

		Expect(k8sClient.Create(ctx, poolA)).To(Succeed())
		Expect(k8sClient.Create(ctx, poolB)).To(Succeed())
		for _, o := range owners {
			Expect(k8sClient.Create(ctx, o)).To(Succeed())
		}
		for _, c := range claims {
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
		}
		DeferCleanup(func() {
			for _, c := range claims {
				_ = k8sClient.Delete(ctx, c)
			}
			for _, o := range owners {
				_ = k8sClient.Delete(ctx, o)
			}
			_ = k8sClient.Delete(ctx, poolA)
			_ = k8sClient.Delete(ctx, poolB)
		})

		reconciler := &AllocationClaimReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		for _, c := range claims {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: c.Name}})
			Expect(err).NotTo(HaveOccurred())
		}

		ips := make([]string, 0, len(claims))
		for _, c := range claims {
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: c.Name}, c)).To(Succeed())
			Expect(c.Status.Phase).To(Equal(juneauv1alpha1.AllocationClaimPhaseAllocated))
			ips = append(ips, c.Status.Value.IP)
		}
		// Two claims fit in poolA (192.0.2.1, 192.0.2.2); the third spills over to poolB (198.51.100.1).
		Expect(ips).To(ConsistOf("192.0.2.1", "192.0.2.2", "198.51.100.1"))
	})
})
