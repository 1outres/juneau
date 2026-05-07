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
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// Reason values surfaced by the ExternalNetwork pool resolver. They are
// exported so consumers (ElasticIPReconciler / ServiceLoadBalancerReconciler)
// can map them onto their own status condition vocabularies without
// re-parsing the error message.
const (
	ExternalNetworkResolveReasonMissingDependency  = "MissingDependency"
	ExternalNetworkResolveReasonInvalidAddressPool = "InvalidAddressPool"
)

// ExternalNetworkResolveError is a typed error returned by
// ResolveExternalNetworkBGPPools when the ExternalNetwork or one of
// its AddressPools is missing or in the wrong mode. The Reason field
// is one of the ExternalNetworkResolveReason* constants and is
// suitable for use as a Status condition Reason.
type ExternalNetworkResolveError struct {
	Reason  string
	Message string
}

func (e *ExternalNetworkResolveError) Error() string {
	return e.Message
}

// ResolveExternalNetworkBGPPools returns the AllocationPool names
// backing the BGP-mode AddressPools attached to the named
// ExternalNetwork, in declaration order. Non-BGP AddressPools (or any
// other resolution failure) cause a typed *ExternalNetworkResolveError
// so callers can mirror the failure into their own status fields.
//
// The resolver is intentionally read-only: it does not create or
// mutate any resource. Pool exhaustion is *not* a resolution failure —
// callers detect that via the AllocationClaim status after a successful
// resolve.
func ResolveExternalNetworkBGPPools(ctx context.Context, c client.Reader, externalNetworkName string) ([]string, error) {
	if strings.TrimSpace(externalNetworkName) == "" {
		return nil, &ExternalNetworkResolveError{
			Reason:  ExternalNetworkResolveReasonMissingDependency,
			Message: "externalNetwork is empty",
		}
	}

	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := c.Get(ctx, client.ObjectKey{Name: externalNetworkName}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			return nil, &ExternalNetworkResolveError{
				Reason:  ExternalNetworkResolveReasonMissingDependency,
				Message: fmt.Sprintf("ExternalNetwork %q not found", externalNetworkName),
			}
		}
		return nil, err
	}

	if len(externalNetwork.Spec.AddressPools) == 0 {
		return nil, &ExternalNetworkResolveError{
			Reason:  ExternalNetworkResolveReasonMissingDependency,
			Message: fmt.Sprintf("ExternalNetwork %q has no AddressPools", externalNetwork.Name),
		}
	}

	poolNames := make([]string, 0, len(externalNetwork.Spec.AddressPools))
	for _, raw := range externalNetwork.Spec.AddressPools {
		poolName := strings.TrimSpace(raw)
		if poolName == "" {
			continue
		}

		var addressPool juneauv1alpha1.AddressPool
		if err := c.Get(ctx, client.ObjectKey{Name: poolName}, &addressPool); err != nil {
			if errors.IsNotFound(err) {
				return nil, &ExternalNetworkResolveError{
					Reason:  ExternalNetworkResolveReasonMissingDependency,
					Message: fmt.Sprintf("AddressPool %q not found", poolName),
				}
			}
			return nil, err
		}

		if addressPool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
			return nil, &ExternalNetworkResolveError{
				Reason:  ExternalNetworkResolveReasonInvalidAddressPool,
				Message: fmt.Sprintf("AddressPool %q advertiseMode must be bgp", addressPool.Name),
			}
		}

		poolNames = append(poolNames, AddressPoolAllocationPoolName(addressPool.Name))
	}

	if len(poolNames) == 0 {
		return nil, &ExternalNetworkResolveError{
			Reason:  ExternalNetworkResolveReasonMissingDependency,
			Message: fmt.Sprintf("ExternalNetwork %q resolves to no usable AddressPools", externalNetwork.Name),
		}
	}

	return poolNames, nil
}
