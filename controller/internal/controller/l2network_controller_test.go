package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/podnetwork"
)

var _ = Describe("L2Network controller", func() {
	It("hands a segment a VNI out of the Subnet pool and the default MTU", func() {
		name := createTestL2Network(createReadyTestVpc(), "")

		l2 := waitForReadyL2Network(name)
		Expect(l2.Status.VNI).NotTo(BeZero())
		Expect(l2.Status.VNI).NotTo(Equal(uint32(1)))
		Expect(l2.Status.MTU).To(Equal(testDefaultL2MTU))
		Expect(l2.Status.Gateway).To(BeEmpty())
		Expect(l2.Status.GatewayMAC).To(BeEmpty())
	})

	It("takes spec.mtu over the controller default", func() {
		vpcName := createReadyTestVpc()
		name := uniqueTestName("l2net")
		l2 := newTestL2Network(name, vpcName, "")
		l2.Spec.MTU = ptr.To(int32(9000))
		Expect(k8sClient.Create(context.Background(), l2)).To(Succeed())

		Expect(waitForReadyL2Network(name).Status.MTU).To(Equal(int32(9000)))
	})

	It("gives two segments different VNIs", func() {
		vpcName := createReadyTestVpc()
		first := waitForReadyL2Network(createTestL2Network(vpcName, ""))
		second := waitForReadyL2Network(createTestL2Network(vpcName, ""))

		Expect(first.Status.VNI).NotTo(Equal(second.Status.VNI))
	})

	It("keeps its VNI claim owned by the segment so deleting it releases the VNI", func() {
		name := createTestL2Network(createReadyTestVpc(), "")
		l2 := waitForReadyL2Network(name)

		var claims juneauv1alpha1.AllocationClaimList
		Expect(k8sClient.List(context.Background(), &claims)).To(Succeed())

		found := false
		for i := range claims.Items {
			claim := &claims.Items[i]
			if claim.Spec.ResourceRef.Kind != "L2Network" || claim.Spec.ResourceRef.Name != name {
				continue
			}
			found = true
			Expect(claim.Spec.PoolRefs[0].Name).To(Equal(allocationPoolSubnetVNI))
			Expect(claim.Spec.ReleaseAfter).To(BeNil())
			owner := metav1.GetControllerOf(claim)
			Expect(owner).NotTo(BeNil())
			Expect(owner.Kind).To(Equal("L2Network"))
			Expect(owner.UID).To(Equal(l2.UID))
		}
		Expect(found).To(BeTrue(), "the L2Network must hold a VNI AllocationClaim")
	})

	It("creates no address pool for a segment without a CIDR", func() {
		name := createTestL2Network(createReadyTestVpc(), "")
		waitForReadyL2Network(name)

		var pool juneauv1alpha1.AllocationPool
		err := k8sClient.Get(context.Background(),
			client.ObjectKey{Name: podnetwork.L2NetworkAllocationPoolName(name)}, &pool)
		Expect(errors.IsNotFound(err)).To(BeTrue(), "a segment without a CIDR hands out no address")
	})

	It("backs a CIDR with an address pool the segment owns", func() {
		name := createTestL2Network(createReadyTestVpc(), "10.150.0.0/24")
		l2 := waitForReadyL2Network(name)

		var pool juneauv1alpha1.AllocationPool
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(context.Background(),
				client.ObjectKey{Name: podnetwork.L2NetworkAllocationPoolName(name)}, &pool)).To(Succeed())
		}).Should(Succeed())

		Expect(pool.Spec.Type).To(Equal(juneauv1alpha1.AllocationTypeIP))
		Expect(pool.Spec.IP.CIDRs).To(Equal([]string{"10.150.0.0/24"}))
		Expect(pool.Spec.IP.Excluded).To(BeEmpty(), "a segment with no gateway reserves nothing")

		owner := metav1.GetControllerOf(&pool)
		Expect(owner).NotTo(BeNil())
		Expect(owner.Kind).To(Equal("L2Network"))
		Expect(owner.UID).To(Equal(l2.UID))
	})

	It("reserves only the gateway, unlike a Subnet which also holds back .2 and .3", func() {
		vpcName := createReadyTestVpc()
		name := uniqueTestName("l2net")
		l2 := newTestL2Network(name, vpcName, "10.151.0.0/24")
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		Expect(k8sClient.Create(context.Background(), l2)).To(Succeed())

		waitForReadyL2Network(name)

		var pool juneauv1alpha1.AllocationPool
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(context.Background(),
				client.ObjectKey{Name: podnetwork.L2NetworkAllocationPoolName(name)}, &pool)).To(Succeed())
			g.Expect(pool.Spec.IP.Excluded).To(Equal([]string{"10.151.0.1"}))
		}).Should(Succeed())
	})

	It("resolves the gateway to the first address and gives it a locally administered MAC", func() {
		vpcName := createReadyTestVpc()
		name := uniqueTestName("l2net")
		l2 := newTestL2Network(name, vpcName, "10.152.0.0/24")
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		Expect(k8sClient.Create(context.Background(), l2)).To(Succeed())

		ready := waitForReadyL2Network(name)
		Expect(ready.Status.Gateway).To(Equal("10.152.0.1"))
		Expect(ready.Status.GatewayMAC).NotTo(BeEmpty())

		// The MAC is an identity attached workloads cache, so it must not
		// change once published.
		Consistently(func(g Gomega) {
			var current juneauv1alpha1.L2Network
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
			g.Expect(current.Status.GatewayMAC).To(Equal(ready.Status.GatewayMAC))
		}, 2*time.Second, 200*time.Millisecond).Should(Succeed())
	})

	It("honours an explicit gateway address", func() {
		vpcName := createReadyTestVpc()
		name := uniqueTestName("l2net")
		l2 := newTestL2Network(name, vpcName, "10.153.0.0/24")
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{Address: "10.153.0.254"}
		Expect(k8sClient.Create(context.Background(), l2)).To(Succeed())

		Expect(waitForReadyL2Network(name).Status.Gateway).To(Equal("10.153.0.254"))
	})

	It("drops the gateway MAC when the gateway goes away", func() {
		vpcName := createReadyTestVpc()
		name := uniqueTestName("l2net")
		l2 := newTestL2Network(name, vpcName, "10.154.0.0/24")
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		Expect(k8sClient.Create(context.Background(), l2)).To(Succeed())
		Expect(waitForReadyL2Network(name).Status.GatewayMAC).NotTo(BeEmpty())

		var current juneauv1alpha1.L2Network
		Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.Gateway = nil
		Expect(k8sClient.Update(context.Background(), &current)).To(Succeed())

		Eventually(func(g Gomega) {
			var updated juneauv1alpha1.L2Network
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &updated)).To(Succeed())
			g.Expect(updated.Status.Gateway).To(BeEmpty())
			g.Expect(updated.Status.GatewayMAC).To(BeEmpty())
		}).Should(Succeed())
	})

	It("stays not ready while its Vpc does not exist", func() {
		name := uniqueTestName("l2net")
		Expect(k8sClient.Create(context.Background(),
			newTestL2Network(name, uniqueTestName("missing-vpc"), ""))).To(Succeed())

		Eventually(func(g Gomega) {
			var l2 juneauv1alpha1.L2Network
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &l2)).To(Succeed())
			ready := meta.FindStatusCondition(l2.Status.Conditions, juneauv1alpha1.L2NetworkStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(l2NetworkReasonVpcNotFound))
		}).Should(Succeed())
	})

	// envtest runs no garbage collector, so a spec can only check the
	// ownerReference the real collector acts on.
	It("leaves every child owned by the segment so deleting it takes them along", func() {
		name := createTestL2Network(createReadyTestVpc(), "10.155.0.0/24")
		l2 := waitForReadyL2Network(name)

		var pool juneauv1alpha1.AllocationPool
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(context.Background(),
				client.ObjectKey{Name: podnetwork.L2NetworkAllocationPoolName(name)}, &pool)).To(Succeed())
		}).Should(Succeed())
		Expect(metav1.GetControllerOf(&pool).UID).To(Equal(l2.UID))

		var claims juneauv1alpha1.AllocationClaimList
		Expect(k8sClient.List(context.Background(), &claims)).To(Succeed())
		for i := range claims.Items {
			claim := &claims.Items[i]
			if claim.Spec.ResourceRef.Kind != "L2Network" || claim.Spec.ResourceRef.Name != name {
				continue
			}
			Expect(metav1.GetControllerOf(claim).UID).To(Equal(l2.UID))
		}

		Expect(k8sClient.Delete(context.Background(), &juneauv1alpha1.L2Network{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		})).To(Succeed())
	})
})

var _ = Describe("NetworkInterface on an L2Network", func() {
	It("becomes Allocated without an address when the segment has no CIDR", func() {
		l2Name := createTestL2Network(createReadyTestVpc(), "")
		waitForReadyL2Network(l2Name)

		iface := newTestL2NetworkInterface(uniqueTestName("nwiface"), l2Name)
		Expect(k8sClient.Create(context.Background(), iface)).To(Succeed())

		reconcileNetworkInterface(iface)

		var current juneauv1alpha1.NetworkInterface
		Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(iface), &current)).To(Succeed())
		Expect(current.Status.Address).To(BeEmpty())
		Expect(current.Status.Routes).To(BeEmpty())
		allocated := meta.FindStatusCondition(current.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusAllocated)
		Expect(allocated).NotTo(BeNil())
		Expect(allocated.Status).To(Equal(metav1.ConditionTrue))
	})

	It("allocates out of the l2network pool when the segment has a CIDR", func() {
		l2Name := createTestL2Network(createReadyTestVpc(), "10.156.0.0/24")
		waitForReadyL2Network(l2Name)

		iface := newTestL2NetworkInterface(uniqueTestName("nwiface"), l2Name)
		Expect(k8sClient.Create(context.Background(), iface)).To(Succeed())

		Eventually(func(g Gomega) {
			reconcileNetworkInterface(iface)

			var current juneauv1alpha1.NetworkInterface
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(iface), &current)).To(Succeed())
			g.Expect(current.Status.Address).To(HavePrefix("10.156.0."))
			g.Expect(current.Status.Address).To(HaveSuffix("/24"))

			var claim juneauv1alpha1.AllocationClaim
			g.Expect(k8sClient.Get(context.Background(),
				client.ObjectKey{Name: current.Status.AllocationClaim}, &claim)).To(Succeed())
			g.Expect(claim.Spec.PoolRefs[0].Name).To(Equal(podnetwork.L2NetworkAllocationPoolName(l2Name)))
		}).Should(Succeed())
	})
})

func newTestL2Network(name, vpcName, cidr string) *juneauv1alpha1.L2Network {
	return &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.L2NetworkSpec{
			Vpc:  vpcName,
			CIDR: cidr,
		},
	}
}

func createTestL2Network(vpcName, cidr string) string {
	name := uniqueTestName("l2net")
	Expect(k8sClient.Create(context.Background(), newTestL2Network(name, vpcName, cidr))).To(Succeed())
	return name
}

func createReadyTestVpc() string {
	name := uniqueTestName("vpc")
	Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})).To(Succeed())

	Eventually(func(g Gomega) {
		var vpc juneauv1alpha1.Vpc
		g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &vpc)).To(Succeed())
		ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
	}).Should(Succeed())
	return name
}

func waitForReadyL2Network(name string) juneauv1alpha1.L2Network {
	var l2 juneauv1alpha1.L2Network
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &l2)).To(Succeed())
		ready := meta.FindStatusCondition(l2.Status.Conditions, juneauv1alpha1.L2NetworkStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		g.Expect(ready.ObservedGeneration).To(Equal(l2.Generation))
	}).Should(Succeed())
	return l2
}

// reconcileNetworkInterface drives the NetworkInterface reconciler once.
// The suite does not run it through the manager, so specs step it by
// hand and observe exactly one pass.
func reconcileNetworkInterface(iface *juneauv1alpha1.NetworkInterface) {
	r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: iface.Name, Namespace: iface.Namespace},
	})
	Expect(err).NotTo(HaveOccurred())
}

func newTestL2NetworkInterface(name, l2Name string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{
				UID:       fmt.Sprintf("uid-%s", name),
				Name:      name,
				Interface: "eth1",
			},
			NodeName:  "node-1",
			L2Network: l2Name,
		},
	}
}
