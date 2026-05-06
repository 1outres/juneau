// Package service drives Juneau's BPF service / backend / affinity
// programming. The reconciler watches Kubernetes Service +
// EndpointSlice events and projects them into the per-Node data plane
// maps (service_map, backend_map, service_acl_map).
//
// The package is structured around three pure stages:
//
//   - resolve.go  collects EndpointSlice rows and resolves each one
//     to a backend candidate (Pod NetworkInterface / underlay).
//   - filter.go   applies BackendSelectionPolicy (iTP=Local, endpoint
//     conditions) to drop unreachable / non-local backends.
//   - program.go  writes the surviving set into BPF and prunes stale
//     keys from the previous reconcile pass.
//
// reconciler.go itself is responsible only for informer wiring
// (Reconcile / FanOut*) and bookkeeping (snapshot map, mutex).
package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
)

// kubernetesServiceLabel links an EndpointSlice to its parent Service
// and is the canonical Kubernetes selector for the relationship.
const kubernetesServiceLabel = "kubernetes.io/service-name"

// Reconciler keeps the BPF service / backend / affinity / ACL maps in
// sync with Kubernetes Service + EndpointSlice resources for this
// Node. nodeName is used by the iTP=Local filter; nodeIP classifies
// host-network backends as HOST_LOCAL versus HOST_REMOTE for the BPF
// fast path.
type Reconciler struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string
	nodeIP    net.IP

	mu        sync.Mutex
	snapshots map[string]programSnapshot
}

// NewReconciler constructs the per-Node Service reconciler. nodeName
// must equal the daemon's --node-name flag so iTP=Local correctly
// recognises endpoints anchored to this Node.
func NewReconciler(cl client.Client, podEgress *program.PodEgress, nodeIP net.IP, nodeName string) *Reconciler {
	return &Reconciler{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
		nodeIP:    nodeIP.To4(),
		snapshots: make(map[string]programSnapshot)}
}

func (r *Reconciler) Name() string { return "service" }

func (r *Reconciler) Reconcile(ctx context.Context, key string) error {
	ns, name, ok := splitNamespacedKey(key)
	if !ok {
		return fmt.Errorf("invalid service key %q", key)
	}

	var svc corev1.Service
	err := r.client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &svc)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	return r.upsert(ctx, key, &svc)
}

func (r *Reconciler) upsert(ctx context.Context, key string, svc *corev1.Service) error {
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return r.delete(key)
	}
	if len(svc.Spec.ClusterIPs) == 0 || svc.Spec.ClusterIP == corev1.ClusterIPNone || svc.Spec.ClusterIP == "" {
		return r.delete(key)
	}

	vpcName := svcpolicy.OwningVpc(svc)

	var vpc juneauv1alpha1.Vpc
	if err := r.client.Get(ctx, client.ObjectKey{Name: vpcName}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			zap.S().Warnf("service: vpc %q not found for %s, deleting entries", vpcName, key)
			return r.delete(key)
		}
		return err
	}
	if vpc.Status.VpcID == 0 {
		// Vpc still being reconciled; skip until it has an ID.
		return nil
	}
	if !vpc.Spec.ServiceEnabled() {
		return r.delete(key)
	}

	clusterIP := net.ParseIP(svc.Spec.ClusterIP).To4()
	if clusterIP == nil {
		zap.S().Warnf("service: %s has non-IPv4 ClusterIP %q", key, svc.Spec.ClusterIP)
		return r.delete(key)
	}
	clusterIPHost := binary.BigEndian.Uint32(clusterIP)

	endpoints, err := r.collectEndpoints(ctx, svc)
	if err != nil {
		return err
	}

	policy := svcpolicy.SelectionPolicyOf(svc)

	resolved, err := r.resolveBackends(ctx, svc, vpcName, endpoints)
	if err != nil {
		return err
	}

	filtered := applyPolicy(resolved, policy, r.nodeName)

	allowedVpcIDs, hasACL, err := r.resolveAllowedConsumerVpcIDs(ctx, svc)
	if err != nil {
		return err
	}

	prev, _ := r.takeSnapshot(key)
	written, err := r.programService(svc, clusterIPHost, &vpc, policy, filtered, allowedVpcIDs, hasACL, prev)
	if err != nil {
		return err
	}
	r.storeSnapshot(key, written)
	r.pruneStale(prev, written)
	return nil
}

func (r *Reconciler) delete(key string) error {
	prev, ok := r.takeSnapshot(key)
	if !ok {
		return nil
	}
	r.deleteSnapshot(prev)
	// Drop the bookkeeping entry as well — otherwise deleted Services
	// leak snapshots indefinitely under churn and subsequent fan-out
	// events keep retrying BPF deletions for already-removed keys.
	r.removeSnapshot(key)
	return nil
}

// FanOutEndpointSliceToService is a keys-func for Runner.WatchFanOut: an
// EndpointSlice change re-enqueues the Service it advertises (the
// "kubernetes.io/service-name" label).
func (r *Reconciler) FanOutEndpointSliceToService(obj any) []string {
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return nil
	}
	svcName := es.Labels[kubernetesServiceLabel]
	if svcName == "" {
		return nil
	}
	return []string{es.Namespace + "/" + svcName}
}

// FanOutAllServices re-enqueues every Service. Used when an upstream
// signal (e.g. NetworkInterface change, Vpc.Status.VpcID allocation,
// Subnet membership shift) cannot be tied to a single Service.
func (r *Reconciler) FanOutAllServices(any) []string {
	var svcs corev1.ServiceList
	if err := r.client.List(context.Background(), &svcs); err != nil {
		zap.S().Warnf("service: list services for fan-out: %v", err)
		return nil
	}
	keys := make([]string, 0, len(svcs.Items))
	for i := range svcs.Items {
		keys = append(keys, svcs.Items[i].Namespace+"/"+svcs.Items[i].Name)
	}
	return keys
}

// resolveAllowedConsumerVpcIDs translates the
// shared-service-allowed-consumer-vpcs annotation into the BPF-side
// vpc_id whitelist. Returns hasACL=false when no ACL is configured
// (every consume-enabled Vpc is admitted by default). Vpcs listed in
// the annotation but not yet reconciled (VpcID=0) or absent from the
// cache are skipped silently; the next Vpc event will re-run the
// reconciler and pick them up.
func (r *Reconciler) resolveAllowedConsumerVpcIDs(ctx context.Context, svc *corev1.Service) ([]uint32, bool, error) {
	allowed := svcpolicy.AllowedConsumerVpcs(svc)
	if len(allowed) == 0 {
		return nil, false, nil
	}
	out := make([]uint32, 0, len(allowed))
	for _, name := range allowed {
		var vpc juneauv1alpha1.Vpc
		if err := r.client.Get(ctx, client.ObjectKey{Name: name}, &vpc); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, false, fmt.Errorf("get consumer Vpc %q: %w", name, err)
		}
		if vpc.Status.VpcID == 0 {
			continue
		}
		out = append(out, vpc.Status.VpcID)
	}
	return out, true, nil
}

func splitNamespacedKey(key string) (string, string, bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}

func protoToU8(proto corev1.Protocol) uint8 {
	switch proto {
	case corev1.ProtocolTCP, "":
		return 6 // IPPROTO_TCP
	case corev1.ProtocolUDP:
		return 17 // IPPROTO_UDP
	default:
		return 0
	}
}

// snapshot helpers operate on the bookkeeping side under r.mu so the
// reconciler is safe to drive from multiple worker goroutines if the
// runner ever raises concurrency above 1.

func (r *Reconciler) takeSnapshot(key string) (programSnapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, ok := r.snapshots[key]
	return prev, ok
}

func (r *Reconciler) storeSnapshot(key string, snap programSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshots[key] = snap
}

func (r *Reconciler) removeSnapshot(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.snapshots, key)
}

// programSnapshot remembers the eBPF map keys this reconciler installed
// for a given Service so deletion / port-set changes can drop stale
// entries. gen is the value last written into service_val.gen so the
// next pass can decide whether to bump it.
type programSnapshot struct {
	serviceKeys []bpf.PodEgressServiceKey
	backendKeys []bpf.PodEgressBackendKey
	aclKeys     []bpf.PodEgressServiceAclKey
	backendSig  string // canonical fingerprint of the previous backend set; gen bumps when it changes
	gen         uint32
}
