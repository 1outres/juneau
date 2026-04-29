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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("AddressPool controller", func() {
	ctx := context.Background()

	It("auto-generates a backing AllocationPool with the BGP CIDRs", func() {
		ap := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: "ap-bgp"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"192.0.2.0/24", "198.51.100.0/30"},
			},
		}
		Expect(k8sClient.Create(ctx, ap)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, ap)
		})

		var pool juneauv1alpha1.AllocationPool
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: AddressPoolAllocationPoolName(ap.Name)}, &pool)).To(Succeed())
			g.Expect(pool.Spec.Type).To(Equal(juneauv1alpha1.AllocationTypeIP))
			g.Expect(pool.Spec.IP).NotTo(BeNil())
			g.Expect(pool.Spec.IP.CIDRs).To(ConsistOf("192.0.2.0/24", "198.51.100.0/30"))
			g.Expect(pool.OwnerReferences).To(HaveLen(1))
			g.Expect(pool.OwnerReferences[0].Kind).To(Equal("AddressPool"))
			g.Expect(pool.OwnerReferences[0].Name).To(Equal(ap.Name))
		}).Should(Succeed())
	})

	It("auto-generates a backing AllocationPool for ARP-mode AddressPools too", func() {
		ap := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: "ap-arp"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeARP,
				Addresses:     []string{"203.0.113.0/29"},
			},
		}
		Expect(k8sClient.Create(ctx, ap)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, ap)
		})

		Eventually(func(g Gomega) {
			var pool juneauv1alpha1.AllocationPool
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: AddressPoolAllocationPoolName(ap.Name)}, &pool)).To(Succeed())
			g.Expect(pool.Spec.Type).To(Equal(juneauv1alpha1.AllocationTypeIP))
			g.Expect(pool.Spec.IP.CIDRs).To(ConsistOf("203.0.113.0/29"))
		}).Should(Succeed())
	})

	It("syncs the CIDR list when the AddressPool spec is updated", func() {
		ap := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: "ap-sync"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"192.0.2.0/24"},
			},
		}
		Expect(k8sClient.Create(ctx, ap)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, ap)
		})

		Eventually(func(g Gomega) {
			var pool juneauv1alpha1.AllocationPool
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: AddressPoolAllocationPoolName(ap.Name)}, &pool)).To(Succeed())
			g.Expect(pool.Spec.IP.CIDRs).To(ConsistOf("192.0.2.0/24"))
		}).Should(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: ap.Name}, ap)).To(Succeed())
		ap.Spec.Addresses = []string{"192.0.2.0/24", "198.51.100.0/30"}
		Expect(k8sClient.Update(ctx, ap)).To(Succeed())

		Eventually(func(g Gomega) {
			var pool juneauv1alpha1.AllocationPool
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: AddressPoolAllocationPoolName(ap.Name)}, &pool)).To(Succeed())
			g.Expect(pool.Spec.IP.CIDRs).To(ConsistOf("192.0.2.0/24", "198.51.100.0/30"))
		}).Should(Succeed())
	})

	It("sets the OwnerReference on the AllocationPool with controller=true and blockOwnerDeletion=true", func() {
		// envtest does not run the K8s garbage collector, so we cannot
		// observe cascade-delete directly. Instead verify that the
		// OwnerReference is wired correctly so that a real cluster's GC
		// will reap the AllocationPool when its AddressPool is deleted.
		ap := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: "ap-ownerref"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"192.0.2.128/29"},
			},
		}
		Expect(k8sClient.Create(ctx, ap)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, ap)
			_ = k8sClient.Delete(ctx, &juneauv1alpha1.AllocationPool{ObjectMeta: metav1.ObjectMeta{Name: AddressPoolAllocationPoolName(ap.Name)}})
		})

		Eventually(func(g Gomega) {
			var pool juneauv1alpha1.AllocationPool
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: AddressPoolAllocationPoolName(ap.Name)}, &pool)).To(Succeed())
			g.Expect(pool.OwnerReferences).To(HaveLen(1))
			ref := pool.OwnerReferences[0]
			g.Expect(ref.Kind).To(Equal("AddressPool"))
			g.Expect(ref.Name).To(Equal(ap.Name))
			g.Expect(ref.UID).To(Equal(ap.UID))
			g.Expect(ref.Controller).NotTo(BeNil())
			g.Expect(*ref.Controller).To(BeTrue())
			g.Expect(ref.BlockOwnerDeletion).NotTo(BeNil())
			g.Expect(*ref.BlockOwnerDeletion).To(BeTrue())
		}).Should(Succeed())
	})
})
