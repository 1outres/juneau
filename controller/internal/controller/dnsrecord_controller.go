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
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	dnsRecordZoneIndex             = "spec.zone"
	dnsRecordNetworkInterfaceIndex = "spec.sources.networkInterface"
	dnsRecordVpcEndpointIndex      = "spec.sources.vpcEndpoint"
	dnsRecordPodNamespaceIndex     = "spec.sources.podSelector.namespace"

	dnsRecordReasonReady             = "Ready"
	dnsRecordReasonZoneNotFound      = "ZoneNotFound"
	dnsRecordReasonZoneNotReady      = "ZoneNotReady"
	dnsRecordReasonDuplicate         = "DuplicateRecord"
	dnsRecordReasonInvalidSource     = "InvalidSource"
	dnsRecordReasonSourceNotFound    = "SourceNotFound"
	dnsRecordReasonSourceVpcMismatch = "SourceVpcMismatch"
	dnsRecordReasonInvalidAddress    = "InvalidAddress"
	dnsRecordReasonTooManyAddresses  = "TooManyAddresses"
)

// DNSRecordReconciler resolves DNSRecord sources and projects their addresses.
type DNSRecordReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type dnsRecordDesiredStatus struct {
	Addresses []string
	Ready     metav1.Condition
}

type dnsRecordFailure struct {
	Reason  string
	Message string
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=dnsrecords,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=dnsrecords/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=dnszones;networkinterfaces;subnets;l2networks;vpcendpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile resolves a DNSRecord as one complete RRset.
func (r *DNSRecordReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var record juneauv1alpha1.DNSRecord
	if err := r.Get(ctx, req.NamespacedName, &record); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !record.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	desired, err := r.buildStatus(ctx, &record)
	if err != nil {
		log.FromContext(ctx).Error(err, "unable to resolve DNSRecord", "name", record.Name)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.updateStatus(ctx, &record, desired)
}

func (r *DNSRecordReconciler) buildStatus(ctx context.Context, record *juneauv1alpha1.DNSRecord) (dnsRecordDesiredStatus, error) {
	var zone juneauv1alpha1.DNSZone
	if err := r.Get(ctx, client.ObjectKey{Name: record.Spec.Zone}, &zone); err != nil {
		if errors.IsNotFound(err) {
			return failedDNSRecordStatus(dnsRecordReasonZoneNotFound, fmt.Sprintf("DNSZone %q does not exist", record.Spec.Zone)), nil
		}
		return dnsRecordDesiredStatus{}, fmt.Errorf("get DNSZone %q: %w", record.Spec.Zone, err)
	}
	ready := meta.FindStatusCondition(zone.Status.Conditions, juneauv1alpha1.DNSZoneConditionReady)
	if !zone.DeletionTimestamp.IsZero() || zone.Status.ObservedGeneration != zone.Generation || ready == nil || ready.Status != metav1.ConditionTrue || ready.ObservedGeneration != zone.Generation {
		return failedDNSRecordStatus(dnsRecordReasonZoneNotReady, fmt.Sprintf("DNSZone %q is not Ready for generation %d", zone.Name, zone.Generation)), nil
	}

	var records juneauv1alpha1.DNSRecordList
	if err := r.List(ctx, &records, client.MatchingFields{dnsRecordZoneIndex: record.Spec.Zone}); err != nil {
		return dnsRecordDesiredStatus{}, fmt.Errorf("list DNSRecords in DNSZone %q: %w", record.Spec.Zone, err)
	}
	for i := range records.Items {
		other := &records.Items[i]
		if other.Name != record.Name && other.Spec.Zone == record.Spec.Zone && other.Spec.Name == record.Spec.Name {
			return failedDNSRecordStatus(dnsRecordReasonDuplicate,
				fmt.Sprintf("DNSRecord %q also defines name %q in DNSZone %q", other.Name, record.Spec.Name, record.Spec.Zone)), nil
		}
	}

	addresses, failure, err := r.resolveSources(ctx, record, &zone)
	if err != nil {
		return dnsRecordDesiredStatus{}, err
	}
	if failure != nil {
		return failedDNSRecordStatus(failure.Reason, failure.Message), nil
	}
	if len(addresses) > 100 {
		return failedDNSRecordStatus(dnsRecordReasonTooManyAddresses,
			fmt.Sprintf("sources resolved to %d unique IPv4 addresses; the limit is 100", len(addresses))), nil
	}
	return dnsRecordDesiredStatus{
		Addresses: addresses,
		Ready: metav1.Condition{Type: juneauv1alpha1.DNSRecordConditionReady, Status: metav1.ConditionTrue,
			Reason: dnsRecordReasonReady, Message: fmt.Sprintf("resolved %d unique IPv4 addresses", len(addresses))},
	}, nil
}

func failedDNSRecordStatus(reason, message string) dnsRecordDesiredStatus {
	return dnsRecordDesiredStatus{Ready: metav1.Condition{
		Type: juneauv1alpha1.DNSRecordConditionReady, Status: metav1.ConditionFalse, Reason: reason, Message: message,
	}}
}

func (r *DNSRecordReconciler) resolveSources(ctx context.Context, record *juneauv1alpha1.DNSRecord, zone *juneauv1alpha1.DNSZone) ([]string, *dnsRecordFailure, error) {
	unique := make(map[string]net.IP)
	snapshots := make(map[string]*dnsPodNamespaceSnapshot)
	addAddress := func(address net.IP) *dnsRecordFailure {
		canonical := address.String()
		if _, exists := unique[canonical]; exists {
			return nil
		}
		unique[canonical] = address.To4()
		if len(unique) > 100 {
			return &dnsRecordFailure{Reason: dnsRecordReasonTooManyAddresses,
				Message: "sources resolved to more than 100 unique IPv4 addresses"}
		}
		return nil
	}

	for i := range record.Spec.Sources {
		source := &record.Spec.Sources[i]
		if dnsSourceKindCount(source) != 1 {
			return nil, &dnsRecordFailure{Reason: dnsRecordReasonInvalidSource,
				Message: fmt.Sprintf("spec.sources[%d] must set exactly one source kind", i)}, nil
		}

		var addresses []net.IP
		var failure *dnsRecordFailure
		var err error
		switch {
		case source.IP != nil:
			var address net.IP
			address, failure = parseIPv4Address(*source.IP, fmt.Sprintf("spec.sources[%d].ip", i))
			if failure == nil {
				addresses = []net.IP{address}
			}
		case source.NetworkInterface != nil:
			addresses, failure, err = r.resolveNetworkInterface(ctx, source.NetworkInterface, zone.Spec.Vpc)
		case source.VpcEndpoint != nil:
			addresses, failure, err = r.resolveVpcEndpoint(ctx, source.VpcEndpoint, zone.Spec.Vpc)
		case source.PodSelector != nil:
			failure, err = r.resolvePodSelector(ctx, source.PodSelector, zone.Spec.Vpc, snapshots, addAddress)
		}
		if err != nil || failure != nil {
			return nil, failure, err
		}
		for _, address := range addresses {
			if failure := addAddress(address); failure != nil {
				return nil, failure, nil
			}
		}
	}

	addresses := make([]net.IP, 0, len(unique))
	for _, address := range unique {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return bytes.Compare(addresses[i], addresses[j]) < 0 })
	result := make([]string, len(addresses))
	for i := range addresses {
		result[i] = addresses[i].String()
	}
	return result, nil, nil
}

func dnsSourceKindCount(source *juneauv1alpha1.DNSRecordSource) int {
	count := 0
	if source.IP != nil {
		count++
	}
	if source.NetworkInterface != nil {
		count++
	}
	if source.VpcEndpoint != nil {
		count++
	}
	if source.PodSelector != nil {
		count++
	}
	return count
}

func (r *DNSRecordReconciler) resolveNetworkInterface(ctx context.Context, source *juneauv1alpha1.DNSNetworkInterfaceSource, zoneVpc string) ([]net.IP, *dnsRecordFailure, error) {
	var networkInterface juneauv1alpha1.NetworkInterface
	key := client.ObjectKey{Namespace: source.Namespace, Name: source.Name}
	if err := r.Get(ctx, key, &networkInterface); err != nil {
		if errors.IsNotFound(err) {
			return nil, &dnsRecordFailure{Reason: dnsRecordReasonSourceNotFound,
				Message: fmt.Sprintf("NetworkInterface %s/%s does not exist", source.Namespace, source.Name)}, nil
		}
		return nil, nil, fmt.Errorf("get NetworkInterface %s: %w", key, err)
	}

	vpc, valid, err := r.networkInterfaceVpc(ctx, &networkInterface)
	if err != nil {
		return nil, nil, err
	}
	if !valid {
		return nil, &dnsRecordFailure{Reason: dnsRecordReasonInvalidSource,
			Message: fmt.Sprintf("NetworkInterface %s/%s does not refer to an existing Subnet or L2Network", source.Namespace, source.Name)}, nil
	}
	if vpc != zoneVpc {
		return nil, &dnsRecordFailure{Reason: dnsRecordReasonSourceVpcMismatch,
			Message: fmt.Sprintf("NetworkInterface %s/%s belongs to Vpc %q, not DNSZone Vpc %q", source.Namespace, source.Name, vpc, zoneVpc)}, nil
	}
	if !networkInterfaceEligible(&networkInterface) {
		return nil, nil, nil
	}
	address, failure := parseIPv4CIDR(networkInterface.Status.Address, fmt.Sprintf("NetworkInterface %s/%s status.address", source.Namespace, source.Name))
	if failure != nil {
		return nil, failure, nil
	}
	return []net.IP{address}, nil, nil
}

func (r *DNSRecordReconciler) resolveVpcEndpoint(ctx context.Context, source *juneauv1alpha1.DNSVpcEndpointSource, zoneVpc string) ([]net.IP, *dnsRecordFailure, error) {
	var endpoint juneauv1alpha1.VpcEndpoint
	if err := r.Get(ctx, client.ObjectKey{Name: source.Name}, &endpoint); err != nil {
		if errors.IsNotFound(err) {
			return nil, &dnsRecordFailure{Reason: dnsRecordReasonSourceNotFound,
				Message: fmt.Sprintf("VpcEndpoint %q does not exist", source.Name)}, nil
		}
		return nil, nil, fmt.Errorf("get VpcEndpoint %q: %w", source.Name, err)
	}
	if endpoint.Spec.Vpc != zoneVpc {
		return nil, &dnsRecordFailure{Reason: dnsRecordReasonSourceVpcMismatch,
			Message: fmt.Sprintf("VpcEndpoint %q belongs to Vpc %q, not DNSZone Vpc %q", source.Name, endpoint.Spec.Vpc, zoneVpc)}, nil
	}
	if !vpcEndpointEligibleForDNS(&endpoint) {
		return nil, nil, nil
	}
	address, failure := parseIPv4Address(endpoint.Status.Address, fmt.Sprintf("VpcEndpoint %q status.address", source.Name))
	if failure != nil {
		return nil, failure, nil
	}
	return []net.IP{address}, nil, nil
}

type dnsPodInterfaceKey struct {
	podUID        string
	interfaceName string
}

type dnsPodNamespaceSnapshot struct {
	pods                     []corev1.Pod
	interfacesByPodInterface map[dnsPodInterfaceKey][]*juneauv1alpha1.NetworkInterface
}

func (r *DNSRecordReconciler) podNamespaceSnapshot(ctx context.Context, namespace string, snapshots map[string]*dnsPodNamespaceSnapshot) (*dnsPodNamespaceSnapshot, error) {
	if snapshot, found := snapshots[namespace]; found {
		return snapshot, nil
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list Pods in namespace %q: %w", namespace, err)
	}
	var interfaces juneauv1alpha1.NetworkInterfaceList
	if err := r.List(ctx, &interfaces, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list NetworkInterfaces in namespace %q: %w", namespace, err)
	}

	snapshot := &dnsPodNamespaceSnapshot{
		pods:                     pods.Items,
		interfacesByPodInterface: make(map[dnsPodInterfaceKey][]*juneauv1alpha1.NetworkInterface),
	}
	for i := range interfaces.Items {
		networkInterface := &interfaces.Items[i]
		key := dnsPodInterfaceKey{podUID: networkInterface.Spec.PodRef.UID, interfaceName: networkInterface.Spec.PodRef.Interface}
		snapshot.interfacesByPodInterface[key] = append(snapshot.interfacesByPodInterface[key], networkInterface)
	}
	snapshots[namespace] = snapshot
	return snapshot, nil
}

func (r *DNSRecordReconciler) resolvePodSelector(
	ctx context.Context,
	source *juneauv1alpha1.DNSPodSelectorSource,
	zoneVpc string,
	snapshots map[string]*dnsPodNamespaceSnapshot,
	addAddress func(net.IP) *dnsRecordFailure,
) (*dnsRecordFailure, error) {
	selector, err := metav1.LabelSelectorAsSelector(&source.Selector)
	if err != nil {
		return &dnsRecordFailure{Reason: dnsRecordReasonInvalidSource,
			Message: fmt.Sprintf("pod selector is invalid: %v", err)}, nil
	}
	if selector.Empty() {
		return &dnsRecordFailure{Reason: dnsRecordReasonInvalidSource, Message: "pod selector must not be empty"}, nil
	}

	snapshot, err := r.podNamespaceSnapshot(ctx, source.Namespace, snapshots)
	if err != nil {
		return nil, err
	}
	for i := range snapshot.pods {
		pod := &snapshot.pods[i]
		if !selector.Matches(labels.Set(pod.Labels)) || !podEligibleForDNS(pod) {
			continue
		}
		key := dnsPodInterfaceKey{podUID: string(pod.UID), interfaceName: source.Interface}
		for _, networkInterface := range snapshot.interfacesByPodInterface[key] {
			if !networkInterfaceEligible(networkInterface) {
				continue
			}
			vpc, valid, err := r.networkInterfaceVpc(ctx, networkInterface)
			if err != nil {
				return nil, err
			}
			if !valid || vpc != zoneVpc {
				continue
			}
			address, failure := parseIPv4CIDR(networkInterface.Status.Address,
				fmt.Sprintf("NetworkInterface %s/%s status.address", networkInterface.Namespace, networkInterface.Name))
			if failure != nil {
				return failure, nil
			}
			if failure := addAddress(address); failure != nil {
				return failure, nil
			}
		}
	}
	return nil, nil
}

func (r *DNSRecordReconciler) networkInterfaceVpc(ctx context.Context, networkInterface *juneauv1alpha1.NetworkInterface) (string, bool, error) {
	switch {
	case networkInterface.Spec.Subnet != "" && networkInterface.Spec.L2Network == "" && networkInterface.Spec.ElasticIP == "":
		var subnet juneauv1alpha1.Subnet
		if err := r.Get(ctx, client.ObjectKey{Name: networkInterface.Spec.Subnet}, &subnet); err != nil {
			if errors.IsNotFound(err) {
				return "", false, nil
			}
			return "", false, fmt.Errorf("get Subnet %q: %w", networkInterface.Spec.Subnet, err)
		}
		return subnet.Spec.Vpc, true, nil
	case networkInterface.Spec.L2Network != "" && networkInterface.Spec.Subnet == "" && networkInterface.Spec.ElasticIP == "":
		var network juneauv1alpha1.L2Network
		if err := r.Get(ctx, client.ObjectKey{Name: networkInterface.Spec.L2Network}, &network); err != nil {
			if errors.IsNotFound(err) {
				return "", false, nil
			}
			return "", false, fmt.Errorf("get L2Network %q: %w", networkInterface.Spec.L2Network, err)
		}
		return network.Spec.Vpc, true, nil
	default:
		return "", false, nil
	}
}

func networkInterfaceEligible(networkInterface *juneauv1alpha1.NetworkInterface) bool {
	if !networkInterface.DeletionTimestamp.IsZero() || networkInterface.Status.ObservedGeneration != networkInterface.Generation {
		return false
	}
	ready := meta.FindStatusCondition(networkInterface.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusReady)
	return ready != nil && ready.Status == metav1.ConditionTrue && ready.ObservedGeneration == networkInterface.Generation
}

func vpcEndpointEligibleForDNS(endpoint *juneauv1alpha1.VpcEndpoint) bool {
	if !endpoint.DeletionTimestamp.IsZero() || endpoint.Status.ObservedGeneration != endpoint.Generation {
		return false
	}
	allocated := meta.FindStatusCondition(endpoint.Status.Conditions, juneauv1alpha1.VpcEndpointConditionAddressAllocated)
	accepted := meta.FindStatusCondition(endpoint.Status.Conditions, juneauv1alpha1.VpcEndpointConditionServiceAccepted)
	return allocated != nil && allocated.Status == metav1.ConditionTrue && allocated.ObservedGeneration == endpoint.Generation &&
		accepted != nil && accepted.Status == metav1.ConditionTrue && accepted.ObservedGeneration == endpoint.Generation
}

func podEligibleForDNS(pod *corev1.Pod) bool {
	if !pod.DeletionTimestamp.IsZero() {
		return false
	}
	for i := range pod.Status.Conditions {
		condition := &pod.Status.Conditions[i]
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func parseIPv4Address(value, source string) (net.IP, *dnsRecordFailure) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return nil, &dnsRecordFailure{Reason: dnsRecordReasonInvalidAddress, Message: fmt.Sprintf("%s %q is not a valid IPv4 address", source, value)}
	}
	return net.IP(address.AsSlice()), nil
}

func parseIPv4CIDR(value, source string) (net.IP, *dnsRecordFailure) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return nil, &dnsRecordFailure{Reason: dnsRecordReasonInvalidAddress, Message: fmt.Sprintf("%s %q is not a valid IPv4 CIDR", source, value)}
	}
	return net.IP(prefix.Addr().AsSlice()), nil
}

func (r *DNSRecordReconciler) updateStatus(ctx context.Context, record *juneauv1alpha1.DNSRecord, desired dnsRecordDesiredStatus) error {
	updated := record.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Addresses = desired.Addresses
	desired.Ready.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, desired.Ready)
	if updated.Status.ObservedGeneration == record.Status.ObservedGeneration &&
		reflect.DeepEqual(updated.Status.Addresses, record.Status.Addresses) && reflect.DeepEqual(updated.Status.Conditions, record.Status.Conditions) {
		return nil
	}
	record.Status = updated.Status
	return r.Status().Update(ctx, record)
}

func (r *DNSRecordReconciler) mapZone(ctx context.Context, obj client.Object) []reconcile.Request {
	zone, ok := obj.(*juneauv1alpha1.DNSZone)
	if !ok {
		return nil
	}
	return r.requestsMatchingField(ctx, dnsRecordZoneIndex, zone.Name)
}

func (r *DNSRecordReconciler) mapIdentityPeers(ctx context.Context, obj client.Object) []reconcile.Request {
	record, ok := obj.(*juneauv1alpha1.DNSRecord)
	if !ok {
		return nil
	}
	var records juneauv1alpha1.DNSRecordList
	if err := r.List(ctx, &records, client.MatchingFields{dnsRecordZoneIndex: record.Spec.Zone}); err != nil {
		log.FromContext(ctx).Error(err, "unable to list DNSRecord conflict peers", "name", record.Name)
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range records.Items {
		if records.Items[i].Spec.Name == record.Spec.Name {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: records.Items[i].Name}})
		}
	}
	return requests
}

func (r *DNSRecordReconciler) mapPod(ctx context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	var records juneauv1alpha1.DNSRecordList
	if err := r.List(ctx, &records, client.MatchingFields{dnsRecordPodNamespaceIndex: pod.Namespace}); err != nil {
		log.FromContext(ctx).Error(err, "unable to list DNSRecords for Pod", "pod", client.ObjectKeyFromObject(pod))
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range records.Items {
		for j := range records.Items[i].Spec.Sources {
			source := records.Items[i].Spec.Sources[j].PodSelector
			if source == nil || source.Namespace != pod.Namespace {
				continue
			}
			selector, err := metav1.LabelSelectorAsSelector(&source.Selector)
			if err == nil && selector.Matches(labels.Set(pod.Labels)) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: records.Items[i].Name}})
				break
			}
		}
	}
	return requests
}

func (r *DNSRecordReconciler) mapNetworkInterface(ctx context.Context, obj client.Object) []reconcile.Request {
	networkInterface, ok := obj.(*juneauv1alpha1.NetworkInterface)
	if !ok {
		return nil
	}
	requests := newDNSRequestSet()
	requests.add(r.requestsMatchingField(ctx, dnsRecordNetworkInterfaceIndex, namespacedDNSKey(networkInterface.Namespace, networkInterface.Name))...)
	requests.add(r.requestsMatchingField(ctx, dnsRecordPodNamespaceIndex, networkInterface.Namespace)...)
	return requests.list()
}

func (r *DNSRecordReconciler) mapVpcEndpoint(ctx context.Context, obj client.Object) []reconcile.Request {
	endpoint, ok := obj.(*juneauv1alpha1.VpcEndpoint)
	if !ok {
		return nil
	}
	return r.requestsMatchingField(ctx, dnsRecordVpcEndpointIndex, endpoint.Name)
}

func (r *DNSRecordReconciler) mapNetworkVpc(ctx context.Context, obj client.Object) []reconcile.Request {
	var vpc string
	switch network := obj.(type) {
	case *juneauv1alpha1.Subnet:
		vpc = network.Spec.Vpc
	case *juneauv1alpha1.L2Network:
		vpc = network.Spec.Vpc
	default:
		return nil
	}
	var zones juneauv1alpha1.DNSZoneList
	if err := r.List(ctx, &zones); err != nil {
		log.FromContext(ctx).Error(err, "unable to list DNSZones for network", "vpc", vpc)
		return nil
	}
	requests := newDNSRequestSet()
	for i := range zones.Items {
		if zones.Items[i].Spec.Vpc == vpc {
			requests.add(r.requestsMatchingField(ctx, dnsRecordZoneIndex, zones.Items[i].Name)...)
		}
	}
	return requests.list()
}

func (r *DNSRecordReconciler) requestsMatchingField(ctx context.Context, fieldName, value string) []reconcile.Request {
	if value == "" {
		return nil
	}
	var records juneauv1alpha1.DNSRecordList
	if err := r.List(ctx, &records, client.MatchingFields{fieldName: value}); err != nil {
		log.FromContext(ctx).Error(err, "unable to list DNSRecords for dependency", "field", fieldName, "value", value)
		return nil
	}
	requests := make([]reconcile.Request, len(records.Items))
	for i := range records.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKey{Name: records.Items[i].Name}}
	}
	return requests
}

type dnsRequestSet map[client.ObjectKey]struct{}

func newDNSRequestSet() dnsRequestSet { return make(dnsRequestSet) }

func (s dnsRequestSet) add(requests ...reconcile.Request) {
	for _, request := range requests {
		s[request.NamespacedName] = struct{}{}
	}
}

func (s dnsRequestSet) list() []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(s))
	for key := range s {
		requests = append(requests, reconcile.Request{NamespacedName: key})
	}
	return requests
}

func namespacedDNSKey(namespace, name string) string { return namespace + "/" + name }

func dnsRecordIndexValues(obj client.Object, pick func(*juneauv1alpha1.DNSRecordSource) string) []string {
	record := obj.(*juneauv1alpha1.DNSRecord)
	values := make(map[string]struct{})
	for i := range record.Spec.Sources {
		if value := pick(&record.Spec.Sources[i]); value != "" {
			values[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return result
}

func indexDNSRecords(ctx context.Context, indexer client.FieldIndexer) error {
	indexes := []struct {
		name string
		pick func(*juneauv1alpha1.DNSRecordSource) string
	}{
		{name: dnsRecordNetworkInterfaceIndex, pick: func(source *juneauv1alpha1.DNSRecordSource) string {
			if source.NetworkInterface == nil {
				return ""
			}
			return namespacedDNSKey(source.NetworkInterface.Namespace, source.NetworkInterface.Name)
		}},
		{name: dnsRecordVpcEndpointIndex, pick: func(source *juneauv1alpha1.DNSRecordSource) string {
			if source.VpcEndpoint == nil {
				return ""
			}
			return source.VpcEndpoint.Name
		}},
		{name: dnsRecordPodNamespaceIndex, pick: func(source *juneauv1alpha1.DNSRecordSource) string {
			if source.PodSelector == nil {
				return ""
			}
			return source.PodSelector.Namespace
		}},
	}
	if err := indexer.IndexField(ctx, &juneauv1alpha1.DNSRecord{}, dnsRecordZoneIndex, func(obj client.Object) []string {
		record := obj.(*juneauv1alpha1.DNSRecord)
		if record.Spec.Zone == "" {
			return nil
		}
		return []string{record.Spec.Zone}
	}); err != nil {
		return fmt.Errorf("index DNSRecords by DNSZone: %w", err)
	}
	for _, index := range indexes {
		if err := indexer.IndexField(ctx, &juneauv1alpha1.DNSRecord{}, index.name, func(obj client.Object) []string {
			return dnsRecordIndexValues(obj, index.pick)
		}); err != nil {
			return fmt.Errorf("index DNSRecords by %s: %w", index.name, err)
		}
	}
	return nil
}

// SetupWithManager sets up the DNSRecord controller.
func (r *DNSRecordReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := indexDNSRecords(context.Background(), mgr.GetFieldIndexer()); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.DNSRecord{}).
		Watches(&juneauv1alpha1.DNSRecord{}, handler.EnqueueRequestsFromMapFunc(r.mapIdentityPeers)).
		Watches(&juneauv1alpha1.DNSZone{}, handler.EnqueueRequestsFromMapFunc(r.mapZone)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPod)).
		Watches(&juneauv1alpha1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkInterface)).
		Watches(&juneauv1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkVpc)).
		Watches(&juneauv1alpha1.L2Network{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkVpc)).
		Watches(&juneauv1alpha1.VpcEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcEndpoint)).
		Named("dnsrecord").
		Complete(r)
}
