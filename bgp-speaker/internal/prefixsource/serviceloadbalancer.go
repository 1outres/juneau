package prefixsource

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceLoadBalancerSource emits VIP/32 advertisements for
// ServiceLoadBalancer resources whose status.advertisingNodes
// contains this speaker's node. The source intentionally does not
// re-derive readiness from EndpointSlices: the SLB controller is
// the single authority on which nodes are eligible to advertise,
// and it stamps status.advertisingNodes accordingly.
//
// The source skips advertisements unless the referenced
// ExternalNetwork is type=bgp; ARP-mode networks have no business
// surfacing /32 routes through bird and would otherwise produce
// spurious BGP updates.
type ServiceLoadBalancerSource struct{}

const serviceLoadBalancerSourceName = "service-loadbalancer"

// Name implements Source.
func (ServiceLoadBalancerSource) Name() string { return serviceLoadBalancerSourceName }

// Build implements Source. Errors that affect a single SLB resource
// are recorded into Result.Errors so the rest of the source set
// keeps publishing.
func (ServiceLoadBalancerSource) Build(ctx context.Context, in Input) (Result, error) {
	var slbs juneauv1alpha1.ServiceLoadBalancerList
	if err := in.Client.List(ctx, &slbs); err != nil {
		return Result{}, fmt.Errorf("list ServiceLoadBalancer: %w", err)
	}

	// Cache resolved ExternalNetworks. A typical cluster has very
	// few of them and many SLBs; one lookup per SLB would be cheap
	// against the speaker's cache, but caching keeps debug log
	// volume low and lets a missing-network error surface only once.
	type netResult struct {
		bgp bool
		err error
	}
	netCache := map[string]netResult{}
	resolveNet := func(name string) netResult {
		if r, ok := netCache[name]; ok {
			return r
		}
		var en juneauv1alpha1.ExternalNetwork
		err := in.Client.Get(ctx, client.ObjectKey{Name: name}, &en)
		var r netResult
		switch {
		case err == nil:
			r.bgp = en.Spec.Type == juneauv1alpha1.ExternalNetworkTypeBGP
		case errors.IsNotFound(err):
			r.err = fmt.Errorf("ExternalNetwork %q not found", name)
		default:
			r.err = err
		}
		netCache[name] = r
		return r
	}

	var advertisements []SourceAdvertisement
	var errs []nodestate.ResourceError

	for i := range slbs.Items {
		slb := &slbs.Items[i]

		if !nodeIn(slb.Status.AdvertisingNodes, in.NodeName) {
			continue
		}

		vip := strings.TrimSpace(slb.Status.VIP)
		if vip == "" {
			continue
		}

		netName := strings.TrimSpace(slb.Spec.ExternalNetwork)
		if netName == "" {
			errs = append(errs, nodestate.ResourceError{
				ResourceKind: "ServiceLoadBalancer",
				ResourceName: slb.Namespace + "/" + slb.Name,
				Message:      "spec.externalNetwork is empty",
			})
			continue
		}
		netRes := resolveNet(netName)
		if netRes.err != nil {
			errs = append(errs, nodestate.ResourceError{
				ResourceKind: "ServiceLoadBalancer",
				ResourceName: slb.Namespace + "/" + slb.Name,
				Message:      netRes.err.Error(),
			})
			continue
		}
		if !netRes.bgp {
			// Not an error: ARP-mode networks announce the VIP with an
			// ARPAdvertisement instead. Surface a soft note so
			// kubectl-juneau users can see why bird has no route for it.
			errs = append(errs, nodestate.ResourceError{
				ResourceKind: "ServiceLoadBalancer",
				ResourceName: slb.Namespace + "/" + slb.Name,
				Message:      fmt.Sprintf("ExternalNetwork %q is ARP-mode; the VIP is announced via ARPAdvertisement", netName),
			})
			continue
		}

		ipnet, err := vipPrefix(vip)
		if err != nil {
			errs = append(errs, nodestate.ResourceError{
				ResourceKind: "ServiceLoadBalancer",
				ResourceName: slb.Namespace + "/" + slb.Name,
				Message:      fmt.Sprintf("invalid VIP %q: %v", vip, err),
			})
			continue
		}

		advertisements = append(advertisements, SourceAdvertisement{
			SourceKind:      "ServiceLoadBalancer",
			SourceNamespace: slb.Namespace,
			SourceName:      slb.Name,
			Prefixes:        []*net.IPNet{ipnet},
		})
	}

	sort.Slice(advertisements, func(i, j int) bool {
		if advertisements[i].SourceNamespace != advertisements[j].SourceNamespace {
			return advertisements[i].SourceNamespace < advertisements[j].SourceNamespace
		}
		return advertisements[i].SourceName < advertisements[j].SourceName
	})

	return Result{
		Advertisements: advertisements,
		Errors:         errs,
	}, nil
}

// vipPrefix turns the IPv4 VIP string from SLB status into a /32
// IPNet. The Phase 1 webhook already enforces IPv4-only, so a
// non-IPv4 VIP here is treated as an error rather than silently
// promoted to a /128 (which would mis-advertise on the IPv4 wire).
func vipPrefix(s string) (*net.IPNet, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("not an IP")
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("VIP must be IPv4")
	}
	return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
}

// nodeIn reports whether the slice contains the given node name. The
// SLB controller already sorts AdvertisingNodes deterministically so
// a binary search would also work; linear scan keeps the source
// readable and the slice is small.
func nodeIn(nodes []string, target string) bool {
	for _, n := range nodes {
		if n == target {
			return true
		}
	}
	return false
}
