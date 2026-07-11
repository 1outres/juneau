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

// LoadBalancerClass is the value Juneau matches on Service
// .spec.loadBalancerClass. Services that set a different class are
// owned by a different LoadBalancer implementation; Juneau ignores
// them. Services that leave the field empty are also ignored by
// default — operators may opt in via a controller flag, but doing so
// races with cloud-provider integrations and is therefore not the
// out-of-the-box behaviour.
//
// The string is part of the user-facing contract and must not be
// changed without a migration story.
const LoadBalancerClass = "juneau.loutres.me/load-balancer"

// Service annotations that drive Juneau-managed LoadBalancer
// behaviour. Constants are co-located with the API types so every
// component (controller, daemon, bgp-speaker, kubectl-juneau) reads
// the same string and there is one place to grep when a name needs
// to evolve.
const (
	// ServiceAnnotationLoadBalancerExternalNetwork selects the
	// cluster-scoped ExternalNetwork from which the VIP is allocated.
	// Required for Juneau-managed LoadBalancer Services.
	ServiceAnnotationLoadBalancerExternalNetwork = "juneau.loutres.me/load-balancer-external-network"

	// ServiceAnnotationLoadBalancerRequestedIP optionally pins a
	// specific VIP. The address must be IPv4 and must fall inside one
	// of the AddressPools backing the selected ExternalNetwork.
	ServiceAnnotationLoadBalancerRequestedIP = "juneau.loutres.me/load-balancer-requested-ip"
)

// ServiceLoadBalancerFinalizer is set on Services and on
// ServiceLoadBalancer resources so the controller can release the
// underlying VIP allocation before the resource disappears.
const ServiceLoadBalancerFinalizer = "serviceloadbalancer.juneau.loutres.me/allocation-claim"
