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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkInterface controller", func() {
	ctx := context.Background()

	allocateNetworkInterface := func(ni *juneauv1alpha1.NetworkInterface) {
		r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Eventually(func(g Gomega) {
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: ni.Name, Namespace: ni.Namespace}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(ni), ni)).To(Succeed())
			g.Expect(ni.Status.Address).NotTo(BeEmpty())
		}).Should(Succeed())
	}

	It("allocates an IP from the subnet via AllocationClaim", func() {
		ni := &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: "ni-alloc.eth0", Namespace: "default"},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef:   juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-alloc", Name: "pod-alloc", Interface: "eth0"},
				NodeName: "node-a",
				Subnet:   "default",
			},
		}
		Expect(k8sClient.Create(ctx, ni)).To(Succeed())
		DeferCleanup(func() { cleanupNetworkInterface(ctx, ni) })

		allocateNetworkInterface(ni)
		Expect(ni.Status.Address).To(MatchRegexp(`^10\.16\.0\.\d+/16$`), "address should be from default subnet 10.16.0.0/16")
		Expect(ni.Status.AllocationClaim).NotTo(BeEmpty())
	})

	It("honors spec.address as a requested IP", func() {
		ni := &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: "ni-fixed.eth0", Namespace: "default"},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef:   juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-fixed", Name: "pod-fixed", Interface: "eth0"},
				NodeName: "node-a",
				Subnet:   "default",
				Address:  "10.16.0.50",
			},
		}
		Expect(k8sClient.Create(ctx, ni)).To(Succeed())
		DeferCleanup(func() { cleanupNetworkInterface(ctx, ni) })

		allocateNetworkInterface(ni)
		Expect(ni.Status.Address).To(Equal("10.16.0.50/16"))
	})

	It("re-uses the same IP when a same-named NetworkInterface is recreated", func() {
		const niName = "ni-reuse.eth0"
		ni := &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: niName, Namespace: "default"},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef:   juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-reuse-1", Name: "pod-reuse", Interface: "eth0"},
				NodeName: "node-a",
				Subnet:   "default",
			},
		}
		Expect(k8sClient.Create(ctx, ni)).To(Succeed())
		allocateNetworkInterface(ni)
		firstAddress := ni.Status.Address
		// lease stores the bare IP (no mask) while NetworkInterface.status.Address
		// includes the subnet mask suffix.
		firstIPOnly, _, _ := strings.Cut(firstAddress, "/")
		claimName := ni.Status.AllocationClaim
		Expect(claimName).NotTo(BeEmpty())

		// Drive the deletion finalizer so the AllocationClaim is removed
		// (which leaves an AllocationLease behind because of ReleaseAfter).
		r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(k8sClient.Delete(ctx, ni)).To(Succeed())
		Eventually(func(g Gomega) {
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: niName, Namespace: "default"}})
			g.Expect(err).NotTo(HaveOccurred())
			err = k8sClient.Get(ctx, client.ObjectKey{Name: niName, Namespace: "default"}, &juneauv1alpha1.NetworkInterface{})
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "NetworkInterface should be deleted after finalizer drains")
		}).Should(Succeed())

		// Lease must persist (ReleaseAfter > 0) and pin the value.
		var lease juneauv1alpha1.AllocationLease
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimName}, &lease)).To(Succeed())
		Expect(lease.Spec.Value.IP).To(Equal(firstIPOnly))

		// Recreate the same-named NetworkInterface.
		recreated := &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: niName, Namespace: "default"},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef:   juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-reuse-2", Name: "pod-reuse", Interface: "eth0"},
				NodeName: "node-a",
				Subnet:   "default",
			},
		}
		Expect(k8sClient.Create(ctx, recreated)).To(Succeed())
		DeferCleanup(func() { cleanupNetworkInterface(ctx, recreated) })

		allocateNetworkInterface(recreated)
		Expect(recreated.Status.Address).To(Equal(firstAddress))
	})

	It("auto-generates a per-subnet AllocationPool with the gateway excluded", func() {
		var pool juneauv1alpha1.AllocationPool
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: SubnetIPAllocationPoolName("default")}, &pool)).To(Succeed())
			g.Expect(pool.Spec.Type).To(Equal(juneauv1alpha1.AllocationTypeIP))
			g.Expect(pool.Spec.IP).NotTo(BeNil())
			g.Expect(pool.Spec.IP.CIDRs).To(ConsistOf("10.16.0.0/16"))
			g.Expect(pool.Spec.IP.Excluded).To(ContainElement("10.16.0.1")) // gateway
		}).Should(Succeed())
	})
})

func cleanupNetworkInterface(ctx context.Context, ni *juneauv1alpha1.NetworkInterface) {
	r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	_ = k8sClient.Delete(ctx, ni)
	// Drive the finalizer once to remove the backing AllocationClaim.
	_, _ = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: ni.Name, Namespace: ni.Namespace}})
	// Best-effort lease cleanup so subsequent tests don't see stale reservations.
	_ = k8sClient.Delete(ctx, &juneauv1alpha1.AllocationLease{ObjectMeta: metav1.ObjectMeta{Name: ni.Status.AllocationClaim}})
}
