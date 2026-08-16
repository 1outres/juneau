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
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const nodeEndpointNamespace = "kube-system"

var _ = Describe("Node controller juneau_node NetworkEndpoint", func() {
	It("publishes the endpoint once the claim is allocated and keeps the daemon's attachment", func() {
		nodeName := "junode-" + time.Now().Format("150405.000000000")[7:]
		reconciler := newEnvtestNodeReconciler()

		Expect(k8sClient.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})).To(Succeed())
		DeferCleanup(func() {
			cleanupNodeTestArtifacts(nodeName)
		})

		var endpoint juneauv1alpha1.NetworkEndpoint
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{
				Namespace: nodeEndpointNamespace,
				Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
			}, &endpoint)).To(Succeed())
		}).Should(Succeed())

		var claim juneauv1alpha1.AllocationClaim
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: JuneauNodeClaimName(nodeName)}, &claim)).To(Succeed())
		Expect(claim.Status.Value.IP).NotTo(BeEmpty())

		Expect(endpoint.Spec.Kind).To(Equal(juneauv1alpha1.EndpointKindNode))
		Expect(endpoint.Spec.NodeName).To(Equal(nodeName))
		Expect(endpoint.Spec.Subnet).To(Equal(JuneauNodeDefaultSubnet))
		Expect(endpoint.Spec.Address).To(Equal(claim.Status.Value.IP + "/16"))
		Expect(endpoint.Spec.MACAddress).To(Equal(mustEndpointMAC(claim.Status.Value.IP)))
		Expect(endpoint.Spec.Attachment).To(BeNil())

		By("letting the daemon record its veth in spec.attachment")
		endpoint.Spec.Attachment = &juneauv1alpha1.NetworkEndpointAttachment{
			Ifindex:        42,
			HostMACAddress: endpoint.Spec.MACAddress,
		}
		Expect(k8sClient.Update(ctx, &endpoint)).To(Succeed())
		createdUID := endpoint.UID

		By("reconciling again and confirming the controller leaves the attachment alone")
		for range 3 {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
			Expect(err).NotTo(HaveOccurred())
		}
		var reread juneauv1alpha1.NetworkEndpoint
		Expect(k8sClient.Get(ctx, client.ObjectKey{
			Namespace: nodeEndpointNamespace,
			Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
		}, &reread)).To(Succeed())
		Expect(reread.UID).To(Equal(createdUID))
		Expect(reread.Spec.Attachment).NotTo(BeNil())
		Expect(reread.Spec.Attachment.Ifindex).To(Equal(42))
	})

	It("republishes the endpoint after it is deleted out of band", func() {
		nodeName := "junode-readd-" + time.Now().Format("150405.000000000")[7:]
		reconciler := newEnvtestNodeReconciler()

		Expect(k8sClient.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})).To(Succeed())
		DeferCleanup(func() {
			cleanupNodeTestArtifacts(nodeName)
		})

		endpointKey := client.ObjectKey{
			Namespace: nodeEndpointNamespace,
			Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
		}

		var published juneauv1alpha1.NetworkEndpoint
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, endpointKey, &published)).To(Succeed())
		}).Should(Succeed())

		By("letting the daemon record its veth, then deleting the endpoint")
		published.Spec.Attachment = &juneauv1alpha1.NetworkEndpointAttachment{
			Ifindex:        42,
			HostMACAddress: published.Spec.MACAddress,
		}
		Expect(k8sClient.Update(ctx, &published)).To(Succeed())
		Expect(k8sClient.Delete(ctx, &published)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(errors.IsNotFound(k8sClient.Get(ctx, endpointKey, &juneauv1alpha1.NetworkEndpoint{}))).To(BeTrue())
		}).Should(Succeed())

		By("checking the deletion maps back to the Node that owns it")
		Expect(mapJuneauNodeEndpointToNode(ctx, &published)).To(Equal([]reconcile.Request{
			{NamespacedName: types.NamespacedName{Name: nodeName}},
		}))

		var fresh juneauv1alpha1.NetworkEndpoint
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, endpointKey, &fresh)).To(Succeed())
		}).Should(Succeed())

		Expect(fresh.UID).NotTo(Equal(published.UID))
		Expect(fresh.Spec.Address).To(Equal(published.Spec.Address))
		Expect(fresh.Spec.MACAddress).To(Equal(published.Spec.MACAddress))
		// The daemon owns the attachment and has to write it again.
		Expect(fresh.Spec.Attachment).To(BeNil())
	})

	It("keeps Pod endpoints out of the Node work queue", func() {
		nodeEndpoint := &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: nodeEndpointNamespace, Name: "juneau-node.worker-1"},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:     juneauv1alpha1.EndpointKindNode,
				NodeName: "worker-1",
			},
		}
		podEndpoint := &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app.eth0"},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:     juneauv1alpha1.EndpointKindPod,
				NodeName: "worker-1",
			},
		}

		for _, tc := range []struct {
			name     string
			endpoint *juneauv1alpha1.NetworkEndpoint
			want     bool
		}{
			{name: "node endpoint", endpoint: nodeEndpoint, want: true},
			{name: "pod endpoint", endpoint: podEndpoint, want: false},
		} {
			By(tc.name)
			Expect(juneauNodeEndpointPredicate.Create(
				event.CreateEvent{Object: tc.endpoint})).To(Equal(tc.want))
			Expect(juneauNodeEndpointPredicate.Delete(
				event.DeleteEvent{Object: tc.endpoint})).To(Equal(tc.want))
			Expect(juneauNodeEndpointPredicate.Update(
				event.UpdateEvent{ObjectOld: tc.endpoint, ObjectNew: tc.endpoint})).To(Equal(tc.want))
			Expect(juneauNodeEndpointPredicate.Generic(
				event.GenericEvent{Object: tc.endpoint})).To(Equal(tc.want))
		}

		By("dropping an endpoint that names no Node")
		unpinned := nodeEndpoint.DeepCopy()
		unpinned.Spec.NodeName = ""
		Expect(mapJuneauNodeEndpointToNode(ctx, unpinned)).To(BeEmpty())
	})

	It("removes the endpoint when the Node is gone", func() {
		nodeName := "junode-gone-" + time.Now().Format("150405.000000000")[7:]
		reconciler := newEnvtestNodeReconciler()

		Expect(k8sClient.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})).To(Succeed())
		DeferCleanup(func() {
			cleanupNodeTestArtifacts(nodeName)
		})

		endpointKey := client.ObjectKey{
			Namespace: nodeEndpointNamespace,
			Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
		}
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, endpointKey, &juneauv1alpha1.NetworkEndpoint{})).To(Succeed())
		}).Should(Succeed())

		Expect(k8sClient.Delete(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})).To(Succeed())
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(errors.IsNotFound(k8sClient.Get(ctx, endpointKey, &juneauv1alpha1.NetworkEndpoint{}))).To(BeTrue())
		}).Should(Succeed())
	})

	It("waits for the claim before publishing anything", func() {
		nodeName := "junode-pending"
		reconciler, c := newFakeNodeReconciler(nodeEndpointNamespace,
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}},
			nodeTestDefaultSubnet(),
			pendingJuneauNodeClaim(nodeName),
		)

		result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))

		err = c.Get(ctx, client.ObjectKey{
			Namespace: nodeEndpointNamespace,
			Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
		}, &juneauv1alpha1.NetworkEndpoint{})
		Expect(errors.IsNotFound(err)).To(BeTrue())
	})

	It("recreates the endpoint when the claim moves to a different IP", func() {
		nodeName := "junode-reallocated"
		stale := &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: nodeEndpointNamespace,
				Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
			},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:       juneauv1alpha1.EndpointKindNode,
				NodeName:   nodeName,
				Subnet:     JuneauNodeDefaultSubnet,
				Address:    "10.16.0.5/16",
				MACAddress: "02:00:0a:10:00:05",
				Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
					Ifindex:        7,
					HostMACAddress: "02:00:0a:10:00:05",
				},
			},
		}
		reconciler, c := newFakeNodeReconciler(nodeEndpointNamespace,
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}},
			nodeTestDefaultSubnet(),
			allocatedJuneauNodeClaim(nodeName, "10.16.0.9"),
			stale,
		)

		endpointKey := client.ObjectKey{
			Namespace: nodeEndpointNamespace,
			Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
		}

		result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).To(BeTrue())
		Expect(errors.IsNotFound(c.Get(ctx, endpointKey, &juneauv1alpha1.NetworkEndpoint{}))).To(BeTrue())

		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
		Expect(err).NotTo(HaveOccurred())

		var fresh juneauv1alpha1.NetworkEndpoint
		Expect(c.Get(ctx, endpointKey, &fresh)).To(Succeed())
		Expect(fresh.Spec.Address).To(Equal("10.16.0.9/16"))
		Expect(fresh.Spec.MACAddress).To(Equal("02:00:0a:10:00:09"))
		Expect(fresh.Spec.Attachment).To(BeNil())
	})

	It("removes an endpoint an older daemon left in its own namespace", func() {
		nodeName := "junode-legacy"
		legacy := &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: nodeEndpointNamespace,
				Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
			},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:       juneauv1alpha1.EndpointKindNode,
				NodeName:   nodeName,
				Subnet:     JuneauNodeDefaultSubnet,
				Address:    "10.16.0.9/16",
				MACAddress: "3e:68:41:95:48:35",
			},
		}
		reconciler, c := newFakeNodeReconciler("juneau-system",
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}},
			nodeTestDefaultSubnet(),
			allocatedJuneauNodeClaim(nodeName, "10.16.0.9"),
			legacy,
		)

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
		Expect(err).NotTo(HaveOccurred())

		Expect(errors.IsNotFound(c.Get(ctx, client.ObjectKeyFromObject(legacy), &juneauv1alpha1.NetworkEndpoint{}))).To(BeTrue())

		var fresh juneauv1alpha1.NetworkEndpoint
		Expect(c.Get(ctx, client.ObjectKey{
			Namespace: "juneau-system",
			Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
		}, &fresh)).To(Succeed())
		Expect(fresh.Spec.MACAddress).To(Equal("02:00:0a:10:00:09"))
	})
})

func newEnvtestNodeReconciler() *NodeReconciler {
	return &NodeReconciler{
		Client:            k8sClient,
		Scheme:            k8sClient.Scheme(),
		EndpointNamespace: nodeEndpointNamespace,
	}
}

func newFakeNodeReconciler(endpointNamespace string, objects ...client.Object) (*NodeReconciler, client.Client) {
	s := runtime.NewScheme()
	Expect(corev1.AddToScheme(s)).To(Succeed())
	Expect(juneauv1alpha1.AddToScheme(s)).To(Succeed())

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objects...).
		WithStatusSubresource(&juneauv1alpha1.AllocationClaim{}).
		Build()

	return &NodeReconciler{Client: c, Scheme: s, EndpointNamespace: endpointNamespace}, c
}

func nodeTestDefaultSubnet() *juneauv1alpha1.Subnet {
	return &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: JuneauNodeDefaultSubnet},
		Spec:       juneauv1alpha1.SubnetSpec{Vpc: defaultVpcName, CIDR: "10.16.0.0/16"},
	}
}

func pendingJuneauNodeClaim(nodeName string) *juneauv1alpha1.AllocationClaim {
	return &juneauv1alpha1.AllocationClaim{
		ObjectMeta: metav1.ObjectMeta{Name: JuneauNodeClaimName(nodeName)},
		Status:     juneauv1alpha1.AllocationClaimStatus{Phase: juneauv1alpha1.AllocationClaimPhasePending},
	}
}

func allocatedJuneauNodeClaim(nodeName, ip string) *juneauv1alpha1.AllocationClaim {
	return &juneauv1alpha1.AllocationClaim{
		ObjectMeta: metav1.ObjectMeta{Name: JuneauNodeClaimName(nodeName)},
		Status: juneauv1alpha1.AllocationClaimStatus{
			Phase: juneauv1alpha1.AllocationClaimPhaseAllocated,
			Value: juneauv1alpha1.AllocationValue{IP: ip},
		},
	}
}

func mustEndpointMAC(ip string) string {
	mac, err := endpointMAC(net.ParseIP(ip))
	Expect(err).NotTo(HaveOccurred())
	return mac
}

func cleanupNodeTestArtifacts(nodeName string) {
	_ = k8sClient.Delete(ctx, &juneauv1alpha1.NetworkEndpoint{ObjectMeta: metav1.ObjectMeta{
		Namespace: nodeEndpointNamespace,
		Name:      juneauv1alpha1.JuneauNodeEndpointName(nodeName),
	}})
	_ = k8sClient.Delete(ctx, &juneauv1alpha1.ServiceNATAttachment{ObjectMeta: metav1.ObjectMeta{
		Name: serviceNATAttachmentName(nodeName, defaultVpcName),
	}})
	_ = k8sClient.Delete(ctx, &juneauv1alpha1.AllocationClaim{ObjectMeta: metav1.ObjectMeta{
		Name: JuneauNodeClaimName(nodeName),
	}})
	_ = k8sClient.Delete(ctx, &juneauv1alpha1.BGPNodeState{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})
	_ = k8sClient.Delete(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})
}
