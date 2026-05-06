package service

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
)

// SVC_FLAG_* mirror the macros in daemon/bpf/maps.h. Keeping them here
// (rather than re-exporting through the bpf package) gives the
// reconciler one obvious place to look up the bit layout.
const (
	svcFlagShared           uint32 = 1 << 0
	svcFlagHasACL           uint32 = 1 << 1
	svcFlagAffinityClientIP uint32 = 1 << 2
	svcFlagInternalLocal    uint32 = 1 << 3
)

// programService writes the per-Service maps for the post-filter
// backend set and returns the new programSnapshot. Backend-set
// changes bump service_val.gen so cached affinity entries are
// invalidated; same-set rewrites preserve the previous gen so a
// chatty client keeps its sticky binding across reconciles.
func (r *Reconciler) programService(
	svc *corev1.Service,
	clusterIPHost uint32,
	vpc *juneauv1alpha1.Vpc,
	policy svcpolicy.BackendSelectionPolicy,
	backendsByPort map[corev1.ServicePort][]resolvedBackend,
	allowedVpcIDs []uint32,
	hasACL bool,
	prev programSnapshot,
) (programSnapshot, error) {
	flags := serviceFlags(svc, policy, hasACL)
	affinitySec := affinitySecondsClamp(policy.Affinity)
	sig := backendSignature(svc, backendsByPort)
	gen := prev.gen
	if sig != prev.backendSig {
		gen++
	}

	out := programSnapshot{backendSig: sig, gen: gen}
	vips := vipsForService(svc, clusterIPHost)
	for _, vip := range vips {
		for _, port := range svc.Spec.Ports {
			proto := protoToU8(port.Protocol)
			if proto == 0 {
				continue
			}
			key := bpf.PodEgressServiceKey{
				ClusterIp: vip,
				Port:      uint16(port.Port),
				Proto:     proto,
			}
			val := bpf.PodEgressServiceVal{
				OwnerVpcId:   vpc.Status.VpcID,
				BackendCount: uint32(len(backendsByPort[port])),
				AffinitySec:  affinitySec,
				Flags:        flags,
				Gen:          gen,
			}
			if err := r.podEgress.Objs.ServiceMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
				return programSnapshot{}, fmt.Errorf("update ServiceMap: %w", err)
			}
			out.serviceKeys = append(out.serviceKeys, key)

			for idx, rb := range backendsByPort[port] {
				bk := bpf.PodEgressBackendKey{
					ClusterIp: vip,
					Port:      uint16(port.Port),
					Proto:     proto,
					Index:     uint32(idx),
				}
				bv := rb.val
				if err := r.podEgress.Objs.BackendMap.Update(&bk, &bv, ebpf.UpdateAny); err != nil {
					return programSnapshot{}, fmt.Errorf("update BackendMap: %w", err)
				}
				out.backendKeys = append(out.backendKeys, bk)
			}

			if hasACL {
				for _, callerVpcID := range allowedVpcIDs {
					ak := bpf.PodEgressServiceAclKey{
						ClusterIp:   vip,
						Port:        uint16(port.Port),
						Proto:       proto,
						CallerVpcId: callerVpcID,
					}
					one := uint8(1)
					if err := r.podEgress.Objs.ServiceAclMap.Update(&ak, &one, ebpf.UpdateAny); err != nil {
						return programSnapshot{}, fmt.Errorf("update ServiceAclMap: %w", err)
					}
					out.aclKeys = append(out.aclKeys, ak)
				}
			}
		}
	}
	return out, nil
}

// vipsForService returns every VIP this Service should be reachable
// at on the data plane: the primary ClusterIP plus any IPv4
// spec.externalIPs entry. Non-IPv4 entries (IPv6, malformed) are
// dropped with a warning so the rest of the Service still programmes
// correctly. Duplicates (e.g. an externalIP equal to the ClusterIP)
// are skipped — service_map updates are last-write-wins, but emitting
// the same key twice would also bloat the snapshot.
func vipsForService(svc *corev1.Service, primaryHost uint32) []uint32 {
	vips := []uint32{primaryHost}
	seen := map[uint32]struct{}{primaryHost: {}}
	for _, raw := range svc.Spec.ExternalIPs {
		ip := net.ParseIP(raw).To4()
		if ip == nil {
			zap.S().Warnf("service: %s/%s skipping non-IPv4 externalIP %q",
				svc.Namespace, svc.Name, raw)
			continue
		}
		host := binary.BigEndian.Uint32(ip)
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		vips = append(vips, host)
	}
	return vips
}

// pruneStale removes BPF entries the previous reconcile pass owned
// but the current pass no longer covers. Inline-deletion ordering
// (service_map last) is irrelevant because the BPF fast path already
// drops misses, so we delete in any order.
func (r *Reconciler) pruneStale(prev, current programSnapshot) {
	for _, sk := range prev.serviceKeys {
		if !containsServiceKey(current.serviceKeys, sk) {
			if err := r.podEgress.Objs.ServiceMap.Delete(&sk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				zap.S().Warnf("service: delete stale ServiceMap entry: %v", err)
			}
		}
	}
	for _, bk := range prev.backendKeys {
		if !containsBackendKey(current.backendKeys, bk) {
			if err := r.podEgress.Objs.BackendMap.Delete(&bk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				zap.S().Warnf("service: delete stale BackendMap entry: %v", err)
			}
		}
	}
	for _, ak := range prev.aclKeys {
		if !containsServiceAclKey(current.aclKeys, ak) {
			if err := r.podEgress.Objs.ServiceAclMap.Delete(&ak); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				zap.S().Warnf("service: delete stale ServiceAclMap entry: %v", err)
			}
		}
	}
}

// deleteSnapshot tears down every BPF entry recorded by snap. Used by
// Reconciler.delete on a Service deletion event.
func (r *Reconciler) deleteSnapshot(snap programSnapshot) {
	for _, sk := range snap.serviceKeys {
		if err := r.podEgress.Objs.ServiceMap.Delete(&sk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("service: delete ServiceMap entry: %v", err)
		}
	}
	for _, bk := range snap.backendKeys {
		if err := r.podEgress.Objs.BackendMap.Delete(&bk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("service: delete BackendMap entry: %v", err)
		}
	}
	for _, ak := range snap.aclKeys {
		if err := r.podEgress.Objs.ServiceAclMap.Delete(&ak); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("service: delete ServiceAclMap entry: %v", err)
		}
	}
}

// serviceFlags returns the SVC_FLAG_* bitmask written to
// service_val.flags for the given Service. The shared decision lives
// in svcpolicy so the BPF backend programmer and the virtual DNS
// resolver answer the same question identically; the ACL bit is
// signalled separately by the caller because resolving the ACL list
// also requires per-consumer-Vpc lookups.
func serviceFlags(svc *corev1.Service, policy svcpolicy.BackendSelectionPolicy, hasACL bool) uint32 {
	var flags uint32
	if svcpolicy.IsShared(svc) {
		flags |= svcFlagShared
	}
	if hasACL {
		flags |= svcFlagHasACL
	}
	if policy.Affinity.Mode == svcpolicy.AffinityClientIP {
		flags |= svcFlagAffinityClientIP
	}
	if policy.InternalLocal {
		flags |= svcFlagInternalLocal
	}
	return flags
}

// affinitySecondsClamp converts policy.Timeout into the seconds value
// stored in service_val.affinity_sec. Returns 0 when affinity is off.
// The clamp guards against pathological future timeouts; Kubernetes
// caps the API at 86400 today.
func affinitySecondsClamp(p svcpolicy.AffinityPolicy) uint32 {
	if p.Mode != svcpolicy.AffinityClientIP || p.Timeout <= 0 {
		return 0
	}
	secs := int64(p.Timeout.Seconds())
	if secs < 1 {
		return 1
	}
	if secs > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(secs)
}

// backendSignature produces a stable fingerprint of the per-port
// backend set. service_val.gen bumps when this fingerprint changes
// across reconciles; matching fingerprints leave gen alone so cached
// affinity bindings remain valid.
//
// The fingerprint is derived from the canonical (port, index, val)
// projection so reordering or unrelated re-resolution noise (e.g. a
// stable Service stale-touch from the FanOut) doesn't bump gen.
func backendSignature(svc *corev1.Service, backendsByPort map[corev1.ServicePort][]resolvedBackend) string {
	h := sha256.New()
	for _, port := range svc.Spec.Ports {
		proto := protoToU8(port.Protocol)
		_ = binary.Write(h, binary.BigEndian, uint16(port.Port))
		_ = binary.Write(h, binary.BigEndian, proto)
		_ = binary.Write(h, binary.BigEndian, uint32(len(backendsByPort[port])))
		// Sort by canonical key so signature is order-independent.
		entries := append([]resolvedBackend(nil), backendsByPort[port]...)
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].val.BackendIp != entries[j].val.BackendIp {
				return entries[i].val.BackendIp < entries[j].val.BackendIp
			}
			if entries[i].val.BackendPort != entries[j].val.BackendPort {
				return entries[i].val.BackendPort < entries[j].val.BackendPort
			}
			return entries[i].val.BackendSubnetId < entries[j].val.BackendSubnetId
		})
		for _, rb := range entries {
			_ = binary.Write(h, binary.BigEndian, rb.val.BackendIp)
			_ = binary.Write(h, binary.BigEndian, rb.val.BackendPort)
			_ = binary.Write(h, binary.BigEndian, rb.val.Kind)
			_ = binary.Write(h, binary.BigEndian, rb.val.BackendSubnetId)
		}
	}
	sum := h.Sum(nil)
	return string(sum)
}

func containsServiceKey(set []bpf.PodEgressServiceKey, k bpf.PodEgressServiceKey) bool {
	for i := range set {
		if set[i] == k {
			return true
		}
	}
	return false
}

func containsBackendKey(set []bpf.PodEgressBackendKey, k bpf.PodEgressBackendKey) bool {
	for i := range set {
		if set[i] == k {
			return true
		}
	}
	return false
}

func containsServiceAclKey(set []bpf.PodEgressServiceAclKey, k bpf.PodEgressServiceAclKey) bool {
	for i := range set {
		if set[i] == k {
			return true
		}
	}
	return false
}
