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
	"net/netip"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/podnetwork"
)

const (
	conditionReasonNetworkNotReady         = "NetworkNotReady"
	conditionReasonWaitingForElasticIP     = "WaitingForElasticIP"
	conditionReasonInvalidElasticIPAddress = "InvalidElasticIPAddress"

	// networkInterfaceElasticIPIndex finds the NetworkInterfaces that name
	// one ElasticIP in spec.elasticIP. Combine it with the namespace of the
	// ElasticIP: a NetworkInterface can only name one of its own namespace.
	networkInterfaceElasticIPIndex = "spec.elasticIP"
)

// reconcileElasticIPAddressing gives an interface that carries an
// ElasticIP the address of that ElasticIP, but only once the ElasticIP
// controller has picked this interface to carry it. Until then the
// interface holds no address at all, so two interfaces never program the
// same address at the same time.
func (r *NetworkInterfaceReconciler) reconcileElasticIPAddressing(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, network *podnetwork.Network) error {
	if waitingFor := elasticIPHolderWait(resource.Name, network.Reference, *network.ElasticIP); waitingFor != "" {
		return r.updateUnaddressedStatus(ctx, resource, conditionReasonWaitingForElasticIP, waitingFor)
	}

	address, err := netip.ParseAddr(network.ElasticIP.Address)
	if err != nil {
		return r.updateAllocationFailureStatus(ctx, resource, conditionReasonInvalidElasticIPAddress,
			fmt.Sprintf("%s holds an address that does not parse: %v", network.Reference, err))
	}
	routes, rules, err := buildElasticIPPodRouting(resource.Spec.PodRef.Interface, address)
	if err != nil {
		return r.updateAllocationFailureStatus(ctx, resource, conditionReasonInvalidElasticIPAddress,
			fmt.Sprintf("%s: %v", network.Reference, err))
	}

	return r.updateAllocatedStatus(ctx, resource, interfaceAddressing{
		address: netip.PrefixFrom(address, address.BitLen()).String(),
		routes:  routes,
		rules:   rules,
		message: fmt.Sprintf("carries the address of %s", network.Reference),
	})
}

// elasticIPHolderWait says why an interface may not carry the address of
// an ElasticIP yet, or returns the empty string when the ElasticIP names
// this interface as the one that carries it.
func elasticIPHolderWait(networkInterface string, ref podnetwork.Reference, binding podnetwork.ElasticIPBinding) string {
	switch {
	case binding.HeldBy(networkInterface):
		return ""
	case binding.Attachment == nil:
		return fmt.Sprintf("%s has not picked a NetworkInterface to carry it yet", ref)
	case binding.Attachment.Kind == juneauv1alpha1.ElasticIPStatusAttachmentKindElasticIPAttachment:
		return fmt.Sprintf("%s is used by ElasticIPAttachment %q", ref, binding.Attachment.Name)
	default:
		return fmt.Sprintf("%s is carried by NetworkInterface %q; this interface takes it over once that one is gone", ref, binding.Attachment.Name)
	}
}

// buildElasticIPPodRouting returns the routes and rules the CNI server
// writes into the Pod network namespace for an interface that holds an
// ElasticIP address as a /32. The gateway is reached on the link.
//
// The primary interface keeps its default route in the main table, as any
// primary interface does. An extra interface cannot put a second default
// route there, so it gets a table of its own, PodElasticIPRouteTable, and
// a rule that sends what leaves from its address to that table.
func buildElasticIPPodRouting(ifName string, address netip.Addr) ([]juneauv1alpha1.NetworkRoute, []juneauv1alpha1.NetworkRoutingRule, error) {
	route := juneauv1alpha1.NetworkRoute{
		Dst:    "0.0.0.0/0",
		GW:     juneauv1alpha1.PodElasticIPGateway,
		OnLink: true,
	}
	if ifName == juneauv1alpha1.PodPrimaryInterfaceName {
		return []juneauv1alpha1.NetworkRoute{route}, nil, nil
	}

	table, err := juneauv1alpha1.PodElasticIPRouteTable(address)
	if err != nil {
		return nil, nil, err
	}
	route.Table = table
	rule := juneauv1alpha1.NetworkRoutingRule{
		From:     netip.PrefixFrom(address, address.BitLen()).String(),
		Table:    table,
		Priority: juneauv1alpha1.PodElasticIPRulePriority,
	}
	return []juneauv1alpha1.NetworkRoute{route}, []juneauv1alpha1.NetworkRoutingRule{rule}, nil
}

// updateUnaddressedStatus leaves the interface Pending with no address
// and no routing. An address it held before is taken back, so the CNI
// server stops programming it on this interface.
func (r *NetworkInterfaceReconciler) updateUnaddressedStatus(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, reason, message string) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Phase = juneauv1alpha1.NetworkInterfacePhasePending
	updated.Status.AllocationClaim = ""
	updated.Status.Address = ""
	updated.Status.Routes = nil
	updated.Status.Rules = nil
	updated.Status.EffectiveSecurityGroups = nil
	for _, conditionType := range []string{juneauv1alpha1.NetworkInterfaceStatusAllocated, juneauv1alpha1.NetworkInterfaceStatusReady} {
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               conditionType,
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: updated.Generation,
		})
	}
	return r.commitStatus(ctx, resource, updated.Status)
}

// mapElasticIPToNetworkInterfaces wakes every NetworkInterface that names
// the ElasticIP, so the one it picks takes the address and the others say
// who they wait for.
func (r *NetworkInterfaceReconciler) mapElasticIPToNetworkInterfaces(ctx context.Context, obj client.Object) []reconcile.Request {
	var interfaces juneauv1alpha1.NetworkInterfaceList
	if err := r.List(ctx, &interfaces,
		client.InNamespace(obj.GetNamespace()),
		client.MatchingFields{networkInterfaceElasticIPIndex: obj.GetName()},
	); err != nil {
		log.FromContext(ctx).Error(err, "unable to list NetworkInterfaces for ElasticIP", "namespace", obj.GetNamespace(), "name", obj.GetName())
		return nil
	}
	requests := make([]reconcile.Request, 0, len(interfaces.Items))
	for i := range interfaces.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&interfaces.Items[i])})
	}
	return requests
}

func indexNetworkInterfaceByElasticIP(ctx context.Context, indexer client.FieldIndexer) error {
	if err := indexer.IndexField(
		ctx,
		&juneauv1alpha1.NetworkInterface{},
		networkInterfaceElasticIPIndex,
		func(obj client.Object) []string {
			nwiface := obj.(*juneauv1alpha1.NetworkInterface)
			if nwiface.Spec.ElasticIP == "" {
				return nil
			}
			return []string{nwiface.Spec.ElasticIP}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for NetworkInterface.%s: %w", networkInterfaceElasticIPIndex, err)
	}
	return nil
}
