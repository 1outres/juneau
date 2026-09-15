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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/addressrange"
)

const (
	addressPoolBGPPrefixMinBits = 8
	addressPoolBGPPrefixMaxBits = 32
)

var (
	errAddressPoolCIDRMalformed = errors.New("must be a valid CIDR")
	errAddressPoolCIDRNotIPv4   = errors.New("only IPv4 CIDR is supported")
	errAddressPoolCIDRPrefix    = fmt.Errorf("prefix must be between /%d and /%d", addressPoolBGPPrefixMinBits, addressPoolBGPPrefixMaxBits)
)

// addressPoolEntryParsers reads one spec.addresses entry in the form its
// advertiseMode asks for. BGP pools write CIDRs and ARP pools write
// start-end ranges; both come out as the range of addresses they hold, so
// pools of either mode can be compared with each other.
var addressPoolEntryParsers = map[juneauv1alpha1.AddressPoolAdvertiseMode]func(string) (addressrange.Range, error){
	juneauv1alpha1.AddressPoolAdvertiseModeBGP: parseAddressPoolCIDR,
	juneauv1alpha1.AddressPoolAdvertiseModeARP: parseAddressPoolRange,
}

// addressPoolSpan is one spec.addresses entry of an AddressPool together
// with the addresses it holds.
type addressPoolSpan struct {
	index int
	raw   string
	addrs addressrange.Range
}

// parseAddressPoolSpans reads every spec.addresses entry of pool. An entry
// that does not fit the advertiseMode becomes a field error on its index and
// yields no span.
func parseAddressPoolSpans(pool *juneauv1alpha1.AddressPool) ([]addressPoolSpan, field.ErrorList) {
	parse, ok := addressPoolEntryParsers[pool.Spec.AdvertiseMode]
	if !ok {
		return nil, field.ErrorList{field.NotSupported(field.NewPath("spec", "advertiseMode"), pool.Spec.AdvertiseMode, supportedAddressPoolAdvertiseModes())}
	}

	addressesPath := field.NewPath("spec", "addresses")
	spans := make([]addressPoolSpan, 0, len(pool.Spec.Addresses))
	var errs field.ErrorList
	for i, raw := range pool.Spec.Addresses {
		addrs, err := parse(raw)
		if err != nil {
			errs = append(errs, field.Invalid(addressesPath.Index(i), raw, err.Error()))
			continue
		}
		spans = append(spans, addressPoolSpan{index: i, raw: raw, addrs: addrs})
	}
	return spans, errs
}

func supportedAddressPoolAdvertiseModes() []juneauv1alpha1.AddressPoolAdvertiseMode {
	modes := make([]juneauv1alpha1.AddressPoolAdvertiseMode, 0, len(addressPoolEntryParsers))
	for mode := range addressPoolEntryParsers {
		modes = append(modes, mode)
	}
	slices.Sort(modes)
	return modes
}

func parseAddressPoolCIDR(raw string) (addressrange.Range, error) {
	_, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		return addressrange.Range{}, errAddressPoolCIDRMalformed
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return addressrange.Range{}, errAddressPoolCIDRNotIPv4
	}
	ones, _ := ipnet.Mask.Size()
	if ones < addressPoolBGPPrefixMinBits || ones > addressPoolBGPPrefixMaxBits {
		return addressrange.Range{}, errAddressPoolCIDRPrefix
	}
	return addressrange.PrefixRange(netip.PrefixFrom(netip.AddrFrom4([4]byte(ip)), ones)), nil
}

func parseAddressPoolRange(raw string) (addressrange.Range, error) {
	start, end, err := addressrange.ParseIPv4Range(raw)
	if err != nil {
		return addressrange.Range{}, err
	}
	return addressrange.Range{Start: start, End: end}, nil
}

// validateAddressPoolOverlaps rejects every entry in claims that shares an
// address with an entry of an AddressPool other than the one named
// poolName. An address that two pools hold can be handed out twice, and the
// data plane cannot tell which ExternalNetwork a packet to it belongs to.
//
// Another pool whose entries do not parse is an error rather than a pool
// that holds nothing: the answer is then unknown, not "no overlap".
func validateAddressPoolOverlaps(ctx context.Context, c client.Reader, poolName string, claims []addressPoolSpan) (field.ErrorList, error) {
	var pools juneauv1alpha1.AddressPoolList
	if err := c.List(ctx, &pools); err != nil {
		return nil, err
	}

	addressesPath := field.NewPath("spec", "addresses")
	var errs field.ErrorList
	for i := range pools.Items {
		other := &pools.Items[i]
		if other.Name == poolName {
			continue
		}
		held, parseErrs := parseAddressPoolSpans(other)
		if len(parseErrs) > 0 {
			return nil, fmt.Errorf("AddressPool %q has an unusable address: %w", other.Name, parseErrs.ToAggregate())
		}
		for _, claim := range claims {
			for _, span := range held {
				shared, ok := claim.addrs.Intersect(span.addrs)
				if !ok {
					continue
				}
				errs = append(errs, field.Invalid(addressesPath.Index(claim.index), claim.raw,
					fmt.Sprintf("overlaps with AddressPool %q address %q at %s", other.Name, span.raw, shared)))
			}
		}
	}
	return errs, nil
}
