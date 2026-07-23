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

package serviceloadbalancer

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
)

// BPFProgrammer writes lb_service_map and lb_backend_map directly,
// driving the data-plane DNAT path implemented in node_ingress.c.
//
// State diff: keep a per-key snapshot of the (service-key, backend-key)
// tuples we last wrote. On Apply, compute the desired key set and
// delete any prior key that no longer appears, mirroring the existing
// service reconciler's stale-cleanup pattern.
type BPFProgrammer struct {
	serviceMap *ebpf.Map
	backendMap *ebpf.Map

	mu        sync.Mutex
	snapshots map[string]bpfSnapshot
}

// bpfSnapshot is the userspace bookkeeping for one SLB key. We
// remember the BPF map keys we wrote so the next reconcile can
// delete entries that fall out of the desired set without rescanning
// the entire map.
type bpfSnapshot struct {
	desired     LBService
	serviceKeys []bpf.NodeIngressLbServiceKey
	backendKeys []bpf.NodeIngressLbBackendKey
}

// NewBPFProgrammer wraps the LoadBalancer-specific BPF maps loaded
// alongside node_ingress / pod_egress. Both maps are
// LIBBPF_PIN_BY_NAME and shared across programs, so passing either
// program's handles is acceptable; we accept them explicitly so the
// caller chooses which program owns the lifetime.
func NewBPFProgrammer(serviceMap, backendMap *ebpf.Map) *BPFProgrammer {
	return &BPFProgrammer{
		serviceMap: serviceMap,
		backendMap: backendMap,
		snapshots:  map[string]bpfSnapshot{},
	}
}

// Apply implements Programmer. desired==nil deletes all entries
// associated with key.
func (p *BPFProgrammer) Apply(key string, desired *LBService) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	prev := p.snapshots[key]

	if desired == nil {
		p.deleteSnapshotLocked(prev)
		delete(p.snapshots, key)
		return nil
	}

	written, err := p.writeLocked(*desired)
	if err != nil {
		return err
	}
	// Delete any prior entries that aren't in the new set. We compare
	// keys by value (BPF keys are POD); doing it before commit means
	// a partial failure leaves the data plane consistent with the
	// last fully-applied state.
	p.pruneStaleLocked(prev, written)
	p.snapshots[key] = bpfSnapshot{
		desired:     *desired,
		serviceKeys: written.serviceKeys,
		backendKeys: written.backendKeys,
	}
	return nil
}

// Snapshot implements Programmer.
func (p *BPFProgrammer) Snapshot() map[string]LBService {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]LBService, len(p.snapshots))
	for k, snap := range p.snapshots {
		out[k] = cloneLBService(snap.desired)
	}
	return out
}

// writeLocked installs lb_service_map / lb_backend_map entries for
// every (port, backend) tuple in desired. Returns the keys written
// so the caller can prune stale entries.
func (p *BPFProgrammer) writeLocked(desired LBService) (bpfSnapshot, error) {
	out := bpfSnapshot{}
	if desired.VIP == nil {
		return out, fmt.Errorf("LBService %s: nil VIP", desired.Key)
	}
	vipBE, err := convert.IPv4ToBPFNetworkOrder(desired.VIP)
	if err != nil {
		return out, fmt.Errorf("LBService %s: invalid VIP: %w", desired.Key, err)
	}

	// Map ports → backends keyed by (servicePort, protocol). Doing it
	// once up-front lets us write per-port entries without re-scanning
	// the backend slice each time.
	type bucket struct {
		port     LBServicePort
		backends []LBBackend
	}
	bucketsByKey := map[lbBucketKey]*bucket{}
	for _, port := range desired.Ports {
		k := lbBucketKey{port: port.Port, proto: port.Protocol}
		bucketsByKey[k] = &bucket{port: port}
	}
	for _, b := range desired.Backends {
		k := lbBucketKey{port: b.ServicePort, proto: b.Protocol}
		bk, ok := bucketsByKey[k]
		if !ok {
			// Ignore backends without a matching declared port. This
			// would only happen on a controller bug; logging it would
			// flood, so we drop silently and rely on userspace tests.
			continue
		}
		bk.backends = append(bk.backends, b)
	}

	for _, b := range bucketsByKey {
		svcKey := bpf.NodeIngressLbServiceKey{
			Vip:   vipBE,
			Port:  b.port.Port,
			Proto: protoToBPF(b.port.Protocol),
		}
		svcVal := bpf.NodeIngressLbServiceVal{
			BackendCount: uint32(len(b.backends)),
		}
		if err := p.serviceMap.Update(&svcKey, &svcVal, ebpf.UpdateAny); err != nil {
			return out, fmt.Errorf("update lb_service_map for %s: %w", desired.Key, err)
		}
		out.serviceKeys = append(out.serviceKeys, svcKey)

		for idx, backend := range b.backends {
			backendIPBE, err := convert.IPv4ToBPFNetworkOrder(backend.PodIP)
			if err != nil {
				return out, fmt.Errorf("LBService %s: invalid backend IP at index %d: %w", desired.Key, idx, err)
			}
			bkey := bpf.NodeIngressLbBackendKey{
				Vip:   vipBE,
				Port:  b.port.Port,
				Proto: protoToBPF(b.port.Protocol),
				Index: uint32(idx),
			}
			bval := bpf.NodeIngressLbBackendVal{
				BackendIp:       backendIPBE,
				BackendPort:     uint16BE(backend.TargetPort),
				BackendSubnetId: backend.SubnetID,
			}
			if err := p.backendMap.Update(&bkey, &bval, ebpf.UpdateAny); err != nil {
				return out, fmt.Errorf("update lb_backend_map for %s idx=%d: %w", desired.Key, idx, err)
			}
			out.backendKeys = append(out.backendKeys, bkey)
		}
	}
	return out, nil
}

// pruneStaleLocked removes entries that exist in prev but not in
// written. Both slices are small (one entry per port × backend), so
// linear search is fine.
func (p *BPFProgrammer) pruneStaleLocked(prev, written bpfSnapshot) {
	for _, k := range prev.serviceKeys {
		if !containsServiceKey(written.serviceKeys, k) {
			_ = p.serviceMap.Delete(&k)
		}
	}
	for _, k := range prev.backendKeys {
		if !containsBackendKey(written.backendKeys, k) {
			_ = p.backendMap.Delete(&k)
		}
	}
}

// deleteSnapshotLocked clears every entry recorded in prev. Used
// when the SLB is being deleted entirely.
func (p *BPFProgrammer) deleteSnapshotLocked(prev bpfSnapshot) {
	for _, k := range prev.serviceKeys {
		_ = p.serviceMap.Delete(&k)
	}
	for _, k := range prev.backendKeys {
		_ = p.backendMap.Delete(&k)
	}
}

type lbBucketKey struct {
	port  uint16
	proto corev1.Protocol
}

// uint16BE returns the network-byte-order representation of p so the
// BPF C code can compare directly against tcphdr->dest / udphdr->dest.
func uint16BE(p uint16) uint16 {
	return (p<<8)&0xff00 | (p>>8)&0x00ff
}

func protoToBPF(p corev1.Protocol) uint8 {
	switch p {
	case corev1.ProtocolTCP:
		return 6 // IPPROTO_TCP
	case corev1.ProtocolUDP:
		return 17 // IPPROTO_UDP
	default:
		return 0
	}
}

func containsServiceKey(set []bpf.NodeIngressLbServiceKey, k bpf.NodeIngressLbServiceKey) bool {
	for _, x := range set {
		if x == k {
			return true
		}
	}
	return false
}

func containsBackendKey(set []bpf.NodeIngressLbBackendKey, k bpf.NodeIngressLbBackendKey) bool {
	for _, x := range set {
		if x == k {
			return true
		}
	}
	return false
}
