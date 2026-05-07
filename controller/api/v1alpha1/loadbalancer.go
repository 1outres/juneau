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

// Service.type=LoadBalancer constants are colocated in the API package
// rather than in any one consumer (controller, webhook, daemon
// svcpolicy) because they form the public contract between user-facing
// Service objects and Juneau-internal LB plumbing. The strings are
// load-bearing across module boundaries — drift would silently break
// admission, allocation, or BPF programming — so a single source of
// truth is mandatory.

const (
	// ServiceLoadBalancerClass is the value of
	// Service.spec.loadBalancerClass that opts a Service.type=LoadBalancer
	// in to Juneau's LB controller. Services without this exact class
	// (or with a foreign class) are ignored end-to-end so MetalLB,
	// cloud-controller-manager, or other LB implementers can coexist in
	// the same cluster.
	ServiceLoadBalancerClass = "juneau.loutres.me/lb"

	// ServiceAnnotationLBExternalNetwork names the ExternalNetwork that
	// backs the LB Service. The chosen ExternalNetwork's BGP-mode
	// AddressPools provide the candidate IP space; the value is
	// validated by the Service admission webhook.
	ServiceAnnotationLBExternalNetwork = "juneau.loutres.me/external-network"

	// ServiceAnnotationLBRequestedIP optionally pins the LB ingress
	// address to a specific IPv4 inside the configured ExternalNetwork's
	// pools. Mirrors ElasticIP.spec.requestedIP semantics. The legacy
	// core spec.loadBalancerIP field is intentionally not honoured —
	// it has been deprecated upstream and using a Juneau-specific
	// annotation keeps the LB pool selector and the IP pin colocated.
	ServiceAnnotationLBRequestedIP = "juneau.loutres.me/loadbalancer-ip"
)
