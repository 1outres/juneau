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
	"fmt"
	"slices"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// elasticIPUse is what uses an ElasticIP, decided from every object that
// names it.
type elasticIPUse struct {
	// attachment is what status.attachment names. Nil when nothing uses
	// the address.
	attachment *juneauv1alpha1.ElasticIPStatusAttachment

	// nodeName is the node that answers ARP for the address. Empty when
	// no single node holds it.
	nodeName string

	// conflict says why the uses cannot stand together. Empty when they
	// can.
	conflict string

	// waitingFor says why no NetworkInterface carries the address even
	// though some name the ElasticIP. Empty otherwise.
	waitingFor string
}

// decideElasticIPUse picks what uses an ElasticIP. previous is the current
// status.attachment, attachments are the ElasticIPAttachments that use it
// and are not being deleted, and interfaces are all NetworkInterfaces that
// name it in spec.elasticIP, deleted or not.
//
// The two kinds of use exclude each other. One ElasticIPAttachment is the
// NAT use. NetworkInterfaces are the direct use, and exactly one of them
// carries the address; selectElasticIPHolder says which.
func decideElasticIPUse(
	previous *juneauv1alpha1.ElasticIPStatusAttachment,
	attachments []juneauv1alpha1.ElasticIPAttachment,
	interfaces []juneauv1alpha1.NetworkInterface,
) elasticIPUse {
	switch {
	case len(attachments) > 1:
		return elasticIPUse{conflict: "multiple ElasticIPAttachments reference this ElasticIP"}
	case len(attachments) == 1 && len(interfaces) > 0:
		return elasticIPUse{conflict: fmt.Sprintf(
			"ElasticIPAttachment %q and NetworkInterface %s both use this ElasticIP; an ElasticIP is used either for NAT or directly, not both",
			attachments[0].Name, networkInterfaceNames(interfaces))}
	case len(attachments) == 1:
		return elasticIPUse{
			attachment: &juneauv1alpha1.ElasticIPStatusAttachment{
				Kind: juneauv1alpha1.ElasticIPStatusAttachmentKindElasticIPAttachment,
				Name: attachments[0].Name,
			},
			nodeName: attachments[0].Status.NodeName,
		}
	case len(interfaces) == 0:
		return elasticIPUse{}
	}

	holder, waitingFor := selectElasticIPHolder(previous, interfaces)
	if holder == nil {
		return elasticIPUse{waitingFor: waitingFor}
	}
	return elasticIPUse{
		attachment: &juneauv1alpha1.ElasticIPStatusAttachment{
			Kind: juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface,
			Name: holder.Name,
		},
		nodeName: holder.Spec.NodeName,
	}
}

// selectElasticIPHolder picks the one NetworkInterface that carries the
// address of an ElasticIP. Only one interface may program the address at
// a time, so the rules never move it away from an interface that may
// still have it:
//
//  1. The interface status.attachment already names keeps the address for
//     as long as it exists, even while it is being deleted.
//  2. Otherwise, while any interface that names the ElasticIP is being
//     deleted, none gets it. Such an interface may be a holder the status
//     no longer remembers, for example after the ElasticIP was in Error.
//  3. Otherwise the oldest interface gets it. Interfaces created in the
//     same second are ordered by name.
//
// When no interface gets the address, the second return value says why.
func selectElasticIPHolder(
	previous *juneauv1alpha1.ElasticIPStatusAttachment,
	interfaces []juneauv1alpha1.NetworkInterface,
) (*juneauv1alpha1.NetworkInterface, string) {
	if holder := retainedElasticIPHolder(previous, interfaces); holder != nil {
		return holder, ""
	}

	var deleting []juneauv1alpha1.NetworkInterface
	for i := range interfaces {
		if !interfaces[i].DeletionTimestamp.IsZero() {
			deleting = append(deleting, interfaces[i])
		}
	}
	if len(deleting) > 0 {
		return nil, fmt.Sprintf("waiting for NetworkInterface %s, which is being deleted, to be gone before another NetworkInterface carries the address",
			networkInterfaceNames(deleting))
	}

	return oldestNetworkInterface(interfaces), ""
}

// retainedElasticIPHolder returns the interface status.attachment names
// when it is still among interfaces, and nil otherwise.
func retainedElasticIPHolder(
	previous *juneauv1alpha1.ElasticIPStatusAttachment,
	interfaces []juneauv1alpha1.NetworkInterface,
) *juneauv1alpha1.NetworkInterface {
	if previous == nil || previous.Kind != juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface {
		return nil
	}
	for i := range interfaces {
		if interfaces[i].Name == previous.Name {
			return &interfaces[i]
		}
	}
	return nil
}

// retainedElasticIPAttachment keeps status.attachment for as long as the
// NetworkInterface it names exists, and drops it otherwise. A deleted
// ElasticIP uses it instead of selectElasticIPHolder, because it hands its
// address to no new NetworkInterface.
func retainedElasticIPAttachment(
	previous *juneauv1alpha1.ElasticIPStatusAttachment,
	interfaces []juneauv1alpha1.NetworkInterface,
) *juneauv1alpha1.ElasticIPStatusAttachment {
	if retainedElasticIPHolder(previous, interfaces) == nil {
		return nil
	}
	return previous.DeepCopy()
}

func oldestNetworkInterface(interfaces []juneauv1alpha1.NetworkInterface) *juneauv1alpha1.NetworkInterface {
	oldest := &interfaces[0]
	for i := 1; i < len(interfaces); i++ {
		candidate := &interfaces[i]
		switch {
		case candidate.CreationTimestamp.Before(&oldest.CreationTimestamp):
			oldest = candidate
		case candidate.CreationTimestamp.Equal(&oldest.CreationTimestamp) && candidate.Name < oldest.Name:
			oldest = candidate
		}
	}
	return oldest
}

// networkInterfaceNames lists the names of interfaces for a message, in a
// stable order.
func networkInterfaceNames(interfaces []juneauv1alpha1.NetworkInterface) string {
	names := make([]string, 0, len(interfaces))
	for i := range interfaces {
		names = append(names, fmt.Sprintf("%q", interfaces[i].Name))
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// mapNetworkInterfaceToElasticIP wakes the ElasticIP a NetworkInterface
// names, so a new, changed or removed interface moves the holder.
func mapNetworkInterfaceToElasticIP(_ context.Context, obj client.Object) []reconcile.Request {
	networkInterface, ok := obj.(*juneauv1alpha1.NetworkInterface)
	if !ok || networkInterface.Spec.ElasticIP == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{Namespace: networkInterface.Namespace, Name: networkInterface.Spec.ElasticIP},
	}}
}
