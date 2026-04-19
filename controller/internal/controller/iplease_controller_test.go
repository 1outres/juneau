package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("IPLease controller", func() {
	It("sets phase Active while ownerDeletionTimestamp is nil", func() {
		name := uniqueTestName("iplease")
		Expect(k8sClient.Create(context.Background(), newControllerIPLease(name, nil, nil))).To(Succeed())
		Expect(reconcileIPLease(name)).To(Succeed())

		lease := getControllerIPLease(name)
		Expect(lease.Status.PodDisplayName).To(Equal("net1.pod-a.default"))
		Expect(lease.Status.Phase).To(Equal(juneauv1alpha1.IPLeasePhaseActive))
		Expect(lease.Status.ExpiresAt).To(BeNil())

		bound := meta.FindStatusCondition(lease.Status.Conditions, juneauv1alpha1.IPLeaseStatusBound)
		Expect(bound).NotTo(BeNil())
		Expect(bound.Status).To(Equal(metav1.ConditionTrue))
		Expect(bound.ObservedGeneration).To(Equal(lease.Generation))

		expired := meta.FindStatusCondition(lease.Status.Conditions, juneauv1alpha1.IPLeaseStatusExpired)
		Expect(expired).NotTo(BeNil())
		Expect(expired.Status).To(Equal(metav1.ConditionFalse))
		Expect(expired.ObservedGeneration).To(Equal(lease.Generation))
	})

	It("sets phase Released while waiting for expiry", func() {
		name := uniqueTestName("iplease")
		ttl := int32(60)
		ownerDeletionTimestamp := metav1.NewTime(time.Now())
		Expect(k8sClient.Create(context.Background(), newControllerIPLease(name, &ownerDeletionTimestamp, &ttl))).To(Succeed())
		Expect(reconcileIPLease(name)).To(Succeed())

		lease := getControllerIPLease(name)
		Expect(lease.Status.Phase).To(Equal(juneauv1alpha1.IPLeasePhaseReleased))
		Expect(lease.Status.ExpiresAt).NotTo(BeNil())
		Expect(lease.Status.ExpiresAt.Time).To(BeTemporally(">", ownerDeletionTimestamp.Time))

		bound := meta.FindStatusCondition(lease.Status.Conditions, juneauv1alpha1.IPLeaseStatusBound)
		Expect(bound).NotTo(BeNil())
		Expect(bound.Status).To(Equal(metav1.ConditionFalse))
		Expect(bound.ObservedGeneration).To(Equal(lease.Generation))

		expired := meta.FindStatusCondition(lease.Status.Conditions, juneauv1alpha1.IPLeaseStatusExpired)
		Expect(expired).NotTo(BeNil())
		Expect(expired.Status).To(Equal(metav1.ConditionFalse))
		Expect(expired.ObservedGeneration).To(Equal(lease.Generation))
	})

	It("sets phase Expired after the TTL has passed", func() {
		name := uniqueTestName("iplease")
		ttl := int32(1)
		ownerDeletionTimestamp := metav1.NewTime(time.Now().Add(-2 * time.Second))
		Expect(k8sClient.Create(context.Background(), newControllerIPLease(name, &ownerDeletionTimestamp, &ttl))).To(Succeed())
		Expect(reconcileIPLease(name)).To(Succeed())

		lease := getControllerIPLease(name)
		Expect(lease.Status.Phase).To(Equal(juneauv1alpha1.IPLeasePhaseExpired))
		Expect(lease.Status.ExpiresAt).NotTo(BeNil())

		bound := meta.FindStatusCondition(lease.Status.Conditions, juneauv1alpha1.IPLeaseStatusBound)
		Expect(bound).NotTo(BeNil())
		Expect(bound.Status).To(Equal(metav1.ConditionFalse))
		Expect(bound.ObservedGeneration).To(Equal(lease.Generation))

		expired := meta.FindStatusCondition(lease.Status.Conditions, juneauv1alpha1.IPLeaseStatusExpired)
		Expect(expired).NotTo(BeNil())
		Expect(expired.Status).To(Equal(metav1.ConditionTrue))
		Expect(expired.ObservedGeneration).To(Equal(lease.Generation))
	})

	It("recomputes expiry from spec instead of stale status", func() {
		name := uniqueTestName("iplease")
		ttl := int32(60)
		ownerDeletionTimestamp := metav1.NewTime(time.Now())
		lease := newControllerIPLease(name, &ownerDeletionTimestamp, &ttl)
		Expect(k8sClient.Create(context.Background(), lease)).To(Succeed())

		lease.Status.ExpiresAt = &metav1.Time{Time: time.Now().Add(-time.Minute)}
		lease.Status.Phase = juneauv1alpha1.IPLeasePhaseExpired
		Expect(k8sClient.Status().Update(context.Background(), lease)).To(Succeed())

		Expect(reconcileIPLease(name)).To(Succeed())

		current := getControllerIPLease(name)
		Expect(current.Status.Phase).To(Equal(juneauv1alpha1.IPLeasePhaseReleased))
		Expect(current.Status.ExpiresAt).NotTo(BeNil())
		Expect(current.Status.ExpiresAt.Time).To(BeTemporally(">", ownerDeletionTimestamp.Time))

		expired := meta.FindStatusCondition(current.Status.Conditions, juneauv1alpha1.IPLeaseStatusExpired)
		Expect(expired).NotTo(BeNil())
		Expect(expired.Status).To(Equal(metav1.ConditionFalse))
	})

	It("deletes itself after spec-derived expiry is observed", func() {
		name := uniqueTestName("iplease")
		ttl := int32(1)
		ownerDeletionTimestamp := metav1.NewTime(time.Now().Add(-2 * time.Second))
		Expect(k8sClient.Create(context.Background(), newControllerIPLease(name, &ownerDeletionTimestamp, &ttl))).To(Succeed())

		Expect(reconcileIPLease(name)).To(Succeed())
		Expect(reconcileIPLease(name)).To(Succeed())

		Eventually(func() bool {
			var lease juneauv1alpha1.IPLease
			err := k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &lease)
			return apierrors.IsNotFound(err)
		}).Should(BeTrue())
	})
})

func newControllerIPLease(name string, ownerDeletionTimestamp *metav1.Time, ttlSeconds *int32) *juneauv1alpha1.IPLease {
	return &juneauv1alpha1.IPLease{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.IPLeaseSpec{
			PodRef: juneauv1alpha1.IPLeasePodReference{
				Namespace: "default",
				Name:      "pod-a",
				Interface: "net1",
			},
			Vpc:                    "default",
			Subnet:                 "default",
			Address:                "10.16.0.10",
			TTLSeconds:             ttlSeconds,
			OwnerDeletionTimeStamp: ownerDeletionTimestamp,
		},
	}
}

func getControllerIPLease(name string) *juneauv1alpha1.IPLease {
	var lease juneauv1alpha1.IPLease
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &lease)).To(Succeed())
	return &lease
}

func reconcileIPLease(name string) error {
	r := &IPLeaseReconciler{Client: k8sClient}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
	return err
}
