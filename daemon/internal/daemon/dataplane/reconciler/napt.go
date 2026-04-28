package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// Napt reconciles per-node NAPT state derived from
// ExternalNetworkAttachments owned by this node:
//
//   - Adds a /32 entry into bgp_address_pools so node_ingress treats
//     packets destined to this node's host_napt_ip as candidates for
//     reverse NAPT (and ElasticIP fall-through).
//
// The forward path (napt_src map population) is implemented in a
// later phase; this reconciler is the place where that write will
// be added.
type Napt struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu   sync.Mutex
	last map[string]bpf.PodEgressBgpAddressPoolsKey // attachment name -> /32 key currently installed
}

func NewNapt(cl client.Client, podEgress *program.PodEgress, nodeName string) *Napt {
	return &Napt{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
		last:      make(map[string]bpf.PodEgressBgpAddressPoolsKey),
	}
}

func (r *Napt) Name() string { return "napt" }

func (r *Napt) Reconcile(ctx context.Context, key string) error {
	var attachment juneauv1alpha1.ExternalNetworkAttachment
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &attachment)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}

	if attachment.Spec.NodeName != r.nodeName {
		// Not our attachment; ensure any stale entry from a prior
		// state is cleaned up.
		return r.delete(key)
	}

	address := strings.TrimSpace(attachment.Status.AssignedIP)
	if address == "" {
		return r.delete(key)
	}

	bgpKey, _, err := parseBGPAddressPoolPrefix(naptHostPrefix(address))
	if err != nil {
		return fmt.Errorf("parse assignedIP %q: %w", address, err)
	}

	var one uint8 = 1
	if err := r.podEgress.Objs.BgpAddressPools.Update(&bgpKey, &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update bgp_address_pools entry for %q: %w", address, err)
	}

	r.mu.Lock()
	if old, ok := r.last[key]; ok && old != bgpKey {
		if err := r.podEgress.Objs.BgpAddressPools.Delete(&old); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			r.mu.Unlock()
			return fmt.Errorf("delete stale bgp_address_pools entry: %w", err)
		}
	}
	r.last[key] = bgpKey
	r.mu.Unlock()
	return nil
}

func (r *Napt) delete(key string) error {
	r.mu.Lock()
	old, ok := r.last[key]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	delete(r.last, key)
	r.mu.Unlock()

	if err := r.podEgress.Objs.BgpAddressPools.Delete(&old); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete bgp_address_pools entry: %w", err)
	}
	return nil
}

func naptHostPrefix(address string) string {
	if strings.Contains(address, "/") {
		return address
	}
	if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
		return address + "/32"
	}
	return address
}

// CloseAll removes every bgp_address_pools entry this reconciler installed.
func (r *Napt) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []error
	for _, key := range r.last {
		if err := r.podEgress.Objs.BgpAddressPools.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	r.last = make(map[string]bpf.PodEgressBgpAddressPoolsKey)
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

