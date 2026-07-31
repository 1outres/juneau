package topology

import (
	"context"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNetworkInterfacesByPodFollowsCurrentAttachment(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Juneau scheme: %v", err)
	}

	current := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "workload"},
	}
	stale := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "workload-stale"},
	}
	currentAttachment := &juneauv1alpha1.NetworkInterfaceAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant-a",
			Name:      "workload-current",
			UID:       types.UID("attachment-current"),
		},
		Spec: juneauv1alpha1.NetworkInterfaceAttachmentSpec{
			NetworkInterfaceRef: current.Name,
			PodRef: juneauv1alpha1.NetworkInterfaceAttachmentPodReference{
				Name: "workload-pod",
				UID:  "pod-current",
			},
		},
	}
	staleAttachment := &juneauv1alpha1.NetworkInterfaceAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant-a",
			Name:      "workload-stale",
			UID:       types.UID("attachment-stale"),
		},
		Spec: juneauv1alpha1.NetworkInterfaceAttachmentSpec{
			NetworkInterfaceRef: stale.Name,
			PodRef: juneauv1alpha1.NetworkInterfaceAttachmentPodReference{
				Name: "workload-pod",
				UID:  "pod-stale",
			},
		},
	}
	current.Spec.AttachmentRef = &juneauv1alpha1.NetworkInterfaceAttachmentReference{
		Name: currentAttachment.Name,
		UID:  currentAttachment.UID,
	}
	stale.Spec.AttachmentRef = &juneauv1alpha1.NetworkInterfaceAttachmentReference{
		Name: staleAttachment.Name,
		UID:  staleAttachment.UID,
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(current, stale, currentAttachment, staleAttachment).
		Build()
	view := NewKubeView(cl)

	got, err := view.NetworkInterfacesByPod(
		context.Background(), "tenant-a", "workload-pod", "pod-current",
	)
	if err != nil {
		t.Fatalf("NetworkInterfacesByPod: %v", err)
	}
	if len(got) != 1 || got[0].Name != current.Name {
		t.Fatalf("got NetworkInterfaces %+v, want only %q", got, current.Name)
	}
}
