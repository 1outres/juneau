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
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// Napt reconciles per-node NAPT state derived from
// ExternalNetworkAttachments owned by this node:
//
//   - Adds a /32 entry into bgp_address_pools so node_ingress treats
//     packets destined to this node's host_napt_ip as candidates for
//     reverse NAPT (and ElasticIP fall-through).
//   - Maintains napt_src[NATGWID] = host_napt_ip for every NATGateway
//     that references the Attachment's ExternalNetwork.
type Napt struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu           sync.Mutex
	bgpInstalled map[string]bpf.PodEgressBgpAddressPoolsKey // attachment -> /32 key
	srcInstalled map[string]map[uint32]struct{}             // attachment -> set of installed NATGWIDs
}

func NewNapt(cl client.Client, podEgress *program.PodEgress, nodeName string) *Napt {
	return &Napt{
		client:       cl,
		podEgress:    podEgress,
		nodeName:     nodeName,
		bgpInstalled: make(map[string]bpf.PodEgressBgpAddressPoolsKey),
		srcInstalled: make(map[string]map[uint32]struct{}),
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
		return r.delete(key)
	}

	address := strings.TrimSpace(attachment.Status.AssignedIP)
	if address == "" {
		return r.delete(key)
	}

	if err := r.upsertBgpAddressPools(key, address); err != nil {
		return err
	}

	if err := r.upsertNaptSrc(ctx, key, &attachment, address); err != nil {
		return err
	}

	return nil
}

func (r *Napt) upsertBgpAddressPools(attachmentName, address string) error {
	bgpKey, _, err := parseBGPAddressPoolPrefix(naptHostPrefix(address))
	if err != nil {
		return fmt.Errorf("parse assignedIP %q: %w", address, err)
	}

	var one uint8 = 1
	if err := r.podEgress.Objs.BgpAddressPools.Update(&bgpKey, &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update bgp_address_pools entry for %q: %w", address, err)
	}

	r.mu.Lock()
	if old, ok := r.bgpInstalled[attachmentName]; ok && old != bgpKey {
		if err := r.podEgress.Objs.BgpAddressPools.Delete(&old); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			r.mu.Unlock()
			return fmt.Errorf("delete stale bgp_address_pools entry: %w", err)
		}
	}
	r.bgpInstalled[attachmentName] = bgpKey
	r.mu.Unlock()
	return nil
}

func (r *Napt) upsertNaptSrc(ctx context.Context, attachmentName string, attachment *juneauv1alpha1.ExternalNetworkAttachment, address string) error {
	hostIP, err := parseAssignedIPForBPF(address)
	if err != nil {
		return fmt.Errorf("parse assignedIP %q: %w", address, err)
	}

	var natGatewayList juneauv1alpha1.NATGatewayList
	if err := r.client.List(ctx, &natGatewayList); err != nil {
		return fmt.Errorf("list NATGateways: %w", err)
	}

	desired := make(map[uint32]struct{})
	for i := range natGatewayList.Items {
		ng := &natGatewayList.Items[i]
		if ng.Spec.ExternalNetwork != attachment.Spec.ExternalNetwork {
			continue
		}
		if ng.Status.GatewayID == 0 {
			continue
		}
		desired[ng.Status.GatewayID] = struct{}{}
	}

	val := bpf.PodEgressNaptSrcVal{HostIp: hostIP}
	for gwID := range desired {
		key := bpf.PodEgressNaptSrcKey{NatGatewayId: gwID}
		if err := r.podEgress.Objs.NaptSrc.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update napt_src[%d]: %w", gwID, err)
		}
	}

	r.mu.Lock()
	old, ok := r.srcInstalled[attachmentName]
	if !ok {
		old = make(map[uint32]struct{})
	}
	for gwID := range old {
		if _, kept := desired[gwID]; kept {
			continue
		}
		key := bpf.PodEgressNaptSrcKey{NatGatewayId: gwID}
		if err := r.podEgress.Objs.NaptSrc.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			r.mu.Unlock()
			return fmt.Errorf("delete stale napt_src[%d]: %w", gwID, err)
		}
	}
	r.srcInstalled[attachmentName] = desired
	r.mu.Unlock()
	return nil
}

func (r *Napt) delete(attachmentName string) error {
	r.mu.Lock()
	bgpKey, hadBgp := r.bgpInstalled[attachmentName]
	if hadBgp {
		delete(r.bgpInstalled, attachmentName)
	}
	srcKeys := r.srcInstalled[attachmentName]
	delete(r.srcInstalled, attachmentName)
	r.mu.Unlock()

	if hadBgp {
		if err := r.podEgress.Objs.BgpAddressPools.Delete(&bgpKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete bgp_address_pools entry: %w", err)
		}
	}
	for gwID := range srcKeys {
		key := bpf.PodEgressNaptSrcKey{NatGatewayId: gwID}
		if err := r.podEgress.Objs.NaptSrc.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete napt_src[%d]: %w", gwID, err)
		}
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

// parseAssignedIPForBPF parses an attachment's assignedIP and encodes
// it for the napt_src.host_ip BPF field, which is consumed as __be32
// (the value is later fed straight into bpf_skb_store_bytes against an
// IP header). On a little-endian host this means the in-memory bytes
// must be NBO; convert.IPv4ToBPFNetworkOrder produces that. The
// previous implementation used binary.BigEndian.Uint32, which on LE
// hosts laid the bytes down in reverse and made the data plane stamp
// packets with a byte-swapped source IP (192.0.2.3 became 3.2.0.192
// on the wire).
func parseAssignedIPForBPF(address string) (uint32, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		if strings.Contains(address, "/") {
			parsed, _, err := net.ParseCIDR(address)
			if err != nil {
				return 0, err
			}
			ip = parsed
		}
	}
	if ip == nil {
		return 0, fmt.Errorf("invalid IP %q", address)
	}
	return convert.IPv4ToBPFNetworkOrder(ip)
}

// FanOutAllAttachments enqueues every owned attachment when an upstream
// resource (e.g. NATGateway) changes — its gatewayID may have flipped.
func (r *Napt) FanOutAllAttachments(any) []string {
	var attachmentList juneauv1alpha1.ExternalNetworkAttachmentList
	if err := r.client.List(context.Background(), &attachmentList); err != nil {
		return nil
	}
	keys := make([]string, 0, len(attachmentList.Items))
	for i := range attachmentList.Items {
		if attachmentList.Items[i].Spec.NodeName != r.nodeName {
			continue
		}
		keys = append(keys, attachmentList.Items[i].Name)
	}
	return keys
}

// CloseAll removes every entry this reconciler installed across all
// attachments.
func (r *Napt) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []error
	for _, bgpKey := range r.bgpInstalled {
		if err := r.podEgress.Objs.BgpAddressPools.Delete(&bgpKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	for _, gwSet := range r.srcInstalled {
		for gwID := range gwSet {
			key := bpf.PodEgressNaptSrcKey{NatGatewayId: gwID}
			if err := r.podEgress.Objs.NaptSrc.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
	}
	r.bgpInstalled = make(map[string]bpf.PodEgressBgpAddressPoolsKey)
	r.srcInstalled = make(map[string]map[uint32]struct{})
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
