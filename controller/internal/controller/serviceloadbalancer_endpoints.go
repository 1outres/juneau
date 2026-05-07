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
	"sort"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// kubernetesServiceLabel is the upstream label EndpointSlices carry
// linking them back to their parent Service.
const kubernetesServiceLabel = "kubernetes.io/service-name"

// endpointSlicesAggregate is the result of summarising the
// EndpointSlices owned by a Service. The aggregate is local to this
// package and exists so the reconciler can attribute a single set of
// status fields (advertisingNodes, totalReady, port resolution) to a
// single API call.
type endpointSlicesAggregate struct {
	// AdvertisingNodes lists nodes that have at least one ready,
	// serving, non-terminating endpoint. The list is deterministically
	// sorted.
	AdvertisingNodes []string
	// TotalReady is the number of distinct ready, serving,
	// non-terminating endpoint addresses across all slices.
	TotalReady int32
	// ResolvedTargetPorts maps a Service port (by name when set, by
	// port number otherwise) to the integer port published in the
	// EndpointSlice. Used to fill SLB ports when the Service uses a
	// string targetPort.
	ResolvedTargetPorts map[servicePortKey]int32
}

// servicePortKey identifies a Service port for the purpose of
// matching it to an EndpointSlice port. Named ports use Name; unnamed
// ports use Number. We split the two on a tag because empty string is
// a valid key in maps but would collide between "no name" and "name
// happens to be empty after trimming," which could cause silent
// mismatches if we ever accept whitespace.
type servicePortKey struct {
	Tag    portKeyTag
	Name   string
	Number int32
}

type portKeyTag uint8

const (
	portKeyByName portKeyTag = iota + 1
	portKeyByNumber
)

func keyForServicePort(p corev1.ServicePort) servicePortKey {
	if p.Name != "" {
		return servicePortKey{Tag: portKeyByName, Name: p.Name}
	}
	return servicePortKey{Tag: portKeyByNumber, Number: p.Port}
}

// collectEndpointAggregate lists the EndpointSlices owned by svc and
// returns a summary suitable for SLB status. The function follows
// upstream EndpointSlice semantics for unset condition fields:
//
//   - Ready defaults to true
//   - Serving defaults to Ready
//   - Terminating defaults to false
//
// Only IPv4 slices are considered in the initial release; Phase 1
// rejected dual-stack/IPv6 Services at admission time, so this matches
// the documented surface.
func (r *ServiceLoadBalancerReconciler) collectEndpointAggregate(ctx context.Context, svc *corev1.Service) (endpointSlicesAggregate, error) {
	var sliceList discoveryv1.EndpointSliceList
	selector := labels.SelectorFromSet(labels.Set{kubernetesServiceLabel: svc.Name})
	if err := r.List(ctx, &sliceList, client.InNamespace(svc.Namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return endpointSlicesAggregate{}, err
	}

	nodeSet := map[string]struct{}{}
	addressSet := map[string]struct{}{}
	resolved := map[servicePortKey]int32{}

	for _, slice := range sliceList.Items {
		if slice.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}

		// Map every Service port to whichever EndpointSlice port it
		// belongs to. Slices may declare multiple ports (e.g. one per
		// named protocol pair); we record the first matching value
		// because Kubernetes guarantees ports are consistent across
		// slices for the same Service.
		for _, ep := range slice.Endpoints {
			ready := condBoolDefault(ep.Conditions.Ready, true)
			serving := condBoolDefault(ep.Conditions.Serving, ready)
			terminating := condBoolDefault(ep.Conditions.Terminating, false)
			if !(ready && serving && !terminating) {
				continue
			}

			node := ""
			if ep.NodeName != nil {
				node = *ep.NodeName
			}
			if node != "" {
				nodeSet[node] = struct{}{}
			}

			for _, addr := range ep.Addresses {
				if addr != "" {
					addressSet[addr] = struct{}{}
				}
			}
		}

		for _, sp := range slice.Ports {
			port := portValueOrZero(sp.Port)
			if port == 0 {
				continue
			}
			if sp.Name != nil && *sp.Name != "" {
				key := servicePortKey{Tag: portKeyByName, Name: *sp.Name}
				if _, exists := resolved[key]; !exists {
					resolved[key] = port
				}
			} else {
				key := servicePortKey{Tag: portKeyByNumber, Number: port}
				if _, exists := resolved[key]; !exists {
					resolved[key] = port
				}
			}
		}
	}

	nodes := make([]string, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	return endpointSlicesAggregate{
		AdvertisingNodes:    nodes,
		TotalReady:          int32(len(addressSet)),
		ResolvedTargetPorts: resolved,
	}, nil
}

// condBoolDefault returns *cond when set, else the provided default.
func condBoolDefault(cond *bool, def bool) bool {
	if cond == nil {
		return def
	}
	return *cond
}

// portValueOrZero unwraps an EndpointSlice port pointer; nil is the
// upstream "any port" sentinel and we treat it as unresolved (0).
func portValueOrZero(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

// resolveTargetPort returns the integer port a Service port maps to,
// taking advantage of the EndpointSlice resolution where available.
// Returns 0 when neither the Service spec nor the EndpointSlice
// resolution is conclusive; the caller decides how to surface that.
func resolveTargetPort(p corev1.ServicePort, agg endpointSlicesAggregate) int32 {
	switch p.TargetPort.Type {
	case intstr.Int:
		if p.TargetPort.IntVal != 0 {
			return p.TargetPort.IntVal
		}
		// Some Services omit targetPort — Kubernetes then defaults it
		// to spec.ports[].port. Mirror that here so dataplane consumers
		// always see a usable integer.
		return p.Port
	case intstr.String:
		if val, ok := agg.ResolvedTargetPorts[keyForServicePort(p)]; ok {
			return val
		}
		return 0
	default:
		return 0
	}
}

// portsFromServiceWithEndpoints is the Phase 3 successor to
// buildPortsFromService: it accepts an EndpointSlice aggregate so
// string targetPorts can be resolved to integers.
func portsFromServiceWithEndpoints(svc *corev1.Service, agg endpointSlicesAggregate) []juneauv1alpha1.ServiceLoadBalancerPort {
	out := make([]juneauv1alpha1.ServiceLoadBalancerPort, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		out = append(out, juneauv1alpha1.ServiceLoadBalancerPort{
			Name:       p.Name,
			Protocol:   p.Protocol,
			Port:       p.Port,
			TargetPort: resolveTargetPort(p, agg),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return string(out[i].Protocol) < string(out[j].Protocol)
	})
	return out
}
