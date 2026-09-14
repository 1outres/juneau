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

package v1alpha1

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// elasticIPDirectUse is a NIC that asks to carry an ElasticIP directly,
// as admission sees it before the NIC exists or while it is created.
type elasticIPDirectUse struct {
	namespace string
	elasticIP string

	// allocationIdentity is the workload identity of the NIC. A holder
	// with the same identity is an earlier instance of the same workload.
	allocationIdentity string

	// networkInterface is the name of the NetworkInterface under
	// admission. Empty when a Pod is admitted and none exists yet.
	networkInterface string

	// podUID is the Pod instance under admission. Its own
	// NetworkInterfaces are not other holders. Empty when a
	// NetworkInterface is admitted, so two interfaces of one Pod on one
	// ElasticIP still collide.
	podUID types.UID
}

// validateElasticIPDirectUse applies the admission rules for carrying an
// ElasticIP directly. A missing or Pending ElasticIP is accepted, so the
// NIC can wait for it. Rejected are an ElasticIP an ElasticIPAttachment
// uses for NAT, and one another NetworkInterface already carries, unless
// that holder is on its way out or belongs to the same workload.
//
// The controller stays the authority for races that admission cannot see,
// such as two NICs admitted at the same moment.
func validateElasticIPDirectUse(ctx context.Context, reader client.Reader, use elasticIPDirectUse, path *field.Path, value any) (field.ErrorList, error) {
	attachment, err := findElasticIPAttachmentUsing(ctx, reader, use.namespace, use.elasticIP)
	if err != nil {
		return nil, err
	}
	if attachment != "" {
		return field.ErrorList{field.Invalid(path, value,
			fmt.Sprintf("ElasticIP %q is used by ElasticIPAttachment %q", use.elasticIP, attachment))}, nil
	}

	var interfaces juneauv1alpha1.NetworkInterfaceList
	if err := reader.List(ctx, &interfaces, client.InNamespace(use.namespace)); err != nil {
		return nil, err
	}
	for i := range interfaces.Items {
		holder := &interfaces.Items[i]
		if holder.Spec.ElasticIP != use.elasticIP || use.isItself(holder) {
			continue
		}
		handsOver, err := elasticIPHolderHandsOver(ctx, reader, holder, use.allocationIdentity)
		if err != nil {
			return nil, err
		}
		if handsOver {
			continue
		}
		return field.ErrorList{field.Invalid(path, value,
			fmt.Sprintf("ElasticIP %q is already used by NetworkInterface %q", use.elasticIP, holder.Name))}, nil
	}
	return nil, nil
}

func (u elasticIPDirectUse) isItself(networkInterface *juneauv1alpha1.NetworkInterface) bool {
	if u.networkInterface != "" && networkInterface.Name == u.networkInterface {
		return true
	}
	return u.podUID != "" && networkInterface.Spec.PodRef.UID == string(u.podUID)
}

// elasticIPHolderHandsOver reports whether a NetworkInterface that carries
// the ElasticIP is about to give it up, so a new NIC may already ask for
// it and wait. That is the case when the holder is being deleted, when its
// Pod instance is gone or Terminating, and when it belongs to the same
// workload, such as the previous virt-launcher Pod of a virtual machine.
func elasticIPHolderHandsOver(ctx context.Context, reader client.Reader, holder *juneauv1alpha1.NetworkInterface, allocationIdentity string) (bool, error) {
	if !holder.DeletionTimestamp.IsZero() {
		return true, nil
	}
	if allocationIdentity != "" && holder.Spec.AllocationIdentity == allocationIdentity {
		return true, nil
	}

	var pod corev1.Pod
	if err := reader.Get(ctx, client.ObjectKey{Namespace: holder.Namespace, Name: holder.Spec.PodRef.Name}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	return string(pod.UID) != holder.Spec.PodRef.UID || !pod.DeletionTimestamp.IsZero(), nil
}

// findElasticIPAttachmentUsing returns the name of an ElasticIPAttachment
// that uses the ElasticIP, or the empty string when none does. One being
// deleted no longer counts, the same way the ElasticIPAttachment webhook
// lets a new attachment replace it.
func findElasticIPAttachmentUsing(ctx context.Context, reader client.Reader, namespace, elasticIP string) (string, error) {
	var attachments juneauv1alpha1.ElasticIPAttachmentList
	if err := reader.List(ctx, &attachments, client.InNamespace(namespace)); err != nil {
		return "", err
	}
	for i := range attachments.Items {
		attachment := &attachments.Items[i]
		if attachment.Spec.ElasticIPRef.Name == elasticIP && attachment.DeletionTimestamp.IsZero() {
			return attachment.Name, nil
		}
	}
	return "", nil
}

// findNetworkInterfaceCarrying returns the name of a NetworkInterface that
// carries the ElasticIP directly, or the empty string when none does.
func findNetworkInterfaceCarrying(ctx context.Context, reader client.Reader, namespace, elasticIP string) (string, error) {
	var interfaces juneauv1alpha1.NetworkInterfaceList
	if err := reader.List(ctx, &interfaces, client.InNamespace(namespace)); err != nil {
		return "", err
	}
	for i := range interfaces.Items {
		networkInterface := &interfaces.Items[i]
		if networkInterface.Spec.ElasticIP == elasticIP && networkInterface.DeletionTimestamp.IsZero() {
			return networkInterface.Name, nil
		}
	}
	return "", nil
}
