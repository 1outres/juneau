package reconciler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
)

const (
	// ServiceAnnotationVpc, ServiceAnnotationShared, and
	// ServiceAnnotationAllowedConsumerVpcs are kept as re-exports so
	// existing callers (including controller-side tests) continue to
	// compile; the canonical home for these constants is the
	// svcpolicy package, which both the data plane and the virtual
	// DNS resolver import.
	ServiceAnnotationVpc                 = svcpolicy.AnnotationVpc
	ServiceAnnotationShared              = svcpolicy.AnnotationShared
	ServiceAnnotationAllowedConsumerVpcs = svcpolicy.AnnotationAllowedConsumerVpcs

	// svcFlagShared mirrors SVC_FLAG_SHARED in daemon/bpf/maps.h. Setting
	// it on service_val.flags lets pod_egress.handle_service treat
	// caller_vpc != owner_vpc as a shared-Service hit instead of a drop.
	svcFlagShared uint32 = 1 << 0
	// svcFlagHasACL mirrors SVC_FLAG_HAS_ACL in daemon/bpf/maps.h.
	// Setting it lets pod_egress.handle_service consult
	// service_acl_map for a (svc × caller_vpc) admit decision.
	svcFlagHasACL uint32 = 1 << 1

	// kubernetesServiceLabel links an EndpointSlice to its parent Service
	// and is the canonical Kubernetes selector for the relationship.
	kubernetesServiceLabel = "kubernetes.io/service-name"

	// backendSubnetIDUnderlay is the sentinel written into
	// backend_val.backend_subnet_id when an endpoint lives on the
	// underlay (a non-Pod target such as kube-apiserver, or a
	// hostNetwork Pod we don't manage). The data plane treats this
	// value as "host-network NAPT path" rather than "Pod backend with
	// VNI 0". Subnet VNIs always start at >=1 (subnet-vni
	// AllocationPool min=2 except the default Subnet which uses 1),
	// so 0 is unambiguously available as a sentinel.
	backendSubnetIDUnderlay uint32 = 0

	// backend_val.kind values; mirror BACKEND_KIND_* in daemon/bpf/maps.h.
	// The reconciler decides which kind a host-network endpoint gets by
	// comparing the endpoint's address to this daemon's own underlay IP.
	// IP equality is the primary signal because EndpointSlice.nodeName is
	// not always populated — kube-apiserver self-manages the kubernetes
	// Service Endpoints and omits nodeName, so a nodeName-based check
	// would slip through and mis-classify a same-node backend as REMOTE.
	backendKindPod        uint8 = 0
	backendKindHostRemote uint8 = 1
	backendKindHostLocal  uint8 = 2
)

// Service keeps service_map and backend_map in sync with Kubernetes
// Service / EndpointSlice resources. A Service maps a ClusterIP+port to
// a set of backend Pods; the reconciler resolves each Pod's IP to a
// NetworkInterface so it can record the backend's Subnet VNI for the
// VXLAN forwarding step in pod_egress.
type Service struct {
	client    client.Client
	podEgress *program.PodEgress
	// nodeIP is this daemon's NodeInternalIP. Used to classify a
	// host-network backend as HOST_LOCAL when its address matches.
	// Same source-of-truth as the host_underlay BPF map slot.
	nodeIP net.IP

	mu        sync.Mutex
	snapshots map[string]serviceSnapshot // service "ns/name" -> entries we wrote
}

// serviceSnapshot remembers the eBPF map keys this reconciler installed
// for a given Service so deletion / port-set changes can drop stale
// entries.
type serviceSnapshot struct {
	serviceKeys []bpf.PodEgressServiceKey
	backendKeys []bpf.PodEgressBackendKey
	aclKeys     []bpf.PodEgressServiceAclKey
}

func NewService(cl client.Client, podEgress *program.PodEgress, nodeIP net.IP) *Service {
	return &Service{
		client:    cl,
		podEgress: podEgress,
		nodeIP:    nodeIP.To4(),
		snapshots: make(map[string]serviceSnapshot),
	}
}

func (r *Service) Name() string { return "service" }

func (r *Service) Reconcile(ctx context.Context, key string) error {
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

func (r *Service) upsert(ctx context.Context, key string, svc *corev1.Service) error {
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

	// Resolve each endpoint to a backend Pod's NetworkInterface so we can
	// pick the Subnet VNI used for VXLAN encap on the egress side.
	backendsByPort := map[corev1.ServicePort][]bpf.PodEgressBackendVal{}

	for _, port := range svc.Spec.Ports {
		matchedEndpoints := matchEndpointsForPort(endpoints, port)
		for _, ep := range matchedEndpoints {
			backendIPStr := ep.address
			if backendIPStr == "" {
				continue
			}
			backendIP := net.ParseIP(backendIPStr).To4()
			if backendIP == nil {
				continue
			}

			var iface *juneauv1alpha1.NetworkInterface
			if ep.targetRef != nil && ep.targetRef.Kind == "Pod" {
				iface, err = r.findInterfaceForPod(ctx, ep.targetRef.Namespace, ep.targetRef.Name)
				if err != nil {
					return err
				}
			}

			// Endpoints that don't map to a NetworkInterface live on the
			// underlay (host-network Pods or non-Pod endpoints such as
			// kube-apiserver). HOST_LOCAL when the endpoint's address is
			// this daemon's own underlay IP — same-node host-network
			// targets need a SNAT-less DNAT path because SNATing to
			// NodeIP would loop the reply through lo where no BPF
			// reverse hook lives. HOST_REMOTE otherwise.
			if iface == nil {
				kind := backendKindHostRemote
				if r.nodeIP != nil && backendIP.Equal(r.nodeIP) {
					kind = backendKindHostLocal
				}
				backendsByPort[port] = append(backendsByPort[port], bpf.PodEgressBackendVal{
					BackendIp:       binary.BigEndian.Uint32(backendIP),
					BackendPort:     uint16(ep.port),
					Kind:            kind,
					BackendSubnetId: backendSubnetIDUnderlay,
				})
				continue
			}

			subnetName := iface.Spec.Subnet
			var subnet juneauv1alpha1.Subnet
			if err := r.client.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return err
			}
			if subnet.Spec.Vpc != vpcName {
				// VPC scope enforcement: ignore backends outside the
				// Service's owning VPC.
				continue
			}
			if subnet.Status.VNI == 0 {
				continue
			}

			backendsByPort[port] = append(backendsByPort[port], bpf.PodEgressBackendVal{
				BackendIp:       binary.BigEndian.Uint32(backendIP),
				BackendPort:     uint16(ep.port),
				Kind:            backendKindPod,
				BackendSubnetId: subnet.Status.VNI,
			})
		}
	}

	// Resolve the consumer ACL once; the same set applies to every
	// (port × proto) row of the Service.
	allowedVpcIDs, hasACL, err := r.resolveAllowedConsumerVpcIDs(ctx, svc)
	if err != nil {
		return err
	}
	flags := serviceFlags(svc, hasACL)

	now := serviceSnapshot{}
	for _, port := range svc.Spec.Ports {
		proto := protoToU8(port.Protocol)
		if proto == 0 {
			continue
		}
		key := bpf.PodEgressServiceKey{
			ClusterIp: clusterIPHost,
			Port:      uint16(port.Port),
			Proto:     proto,
		}
		val := bpf.PodEgressServiceVal{
			OwnerVpcId:   vpc.Status.VpcID,
			BackendCount: uint32(len(backendsByPort[port])),
			Flags:        flags,
		}
		if err := r.podEgress.Objs.ServiceMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update ServiceMap: %w", err)
		}
		now.serviceKeys = append(now.serviceKeys, key)

		for idx, bv := range backendsByPort[port] {
			bk := bpf.PodEgressBackendKey{
				ClusterIp: clusterIPHost,
				Port:      uint16(port.Port),
				Proto:     proto,
				Index:     uint32(idx),
			}
			if err := r.podEgress.Objs.BackendMap.Update(&bk, &bv, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update BackendMap: %w", err)
			}
			now.backendKeys = append(now.backendKeys, bk)
		}

		if hasACL {
			for _, callerVpcID := range allowedVpcIDs {
				ak := bpf.PodEgressServiceAclKey{
					ClusterIp:   clusterIPHost,
					Port:        uint16(port.Port),
					Proto:       proto,
					CallerVpcId: callerVpcID,
				}
				one := uint8(1)
				if err := r.podEgress.Objs.ServiceAclMap.Update(&ak, &one, ebpf.UpdateAny); err != nil {
					return fmt.Errorf("update ServiceAclMap: %w", err)
				}
				now.aclKeys = append(now.aclKeys, ak)
			}
		}
	}

	// Drop stale entries from the previous reconcile pass.
	r.mu.Lock()
	old := r.snapshots[key]
	r.snapshots[key] = now
	r.mu.Unlock()

	for _, sk := range old.serviceKeys {
		if !containsServiceKey(now.serviceKeys, sk) {
			if err := r.podEgress.Objs.ServiceMap.Delete(&sk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				zap.S().Warnf("service: delete stale ServiceMap entry: %v", err)
			}
		}
	}
	for _, bk := range old.backendKeys {
		if !containsBackendKey(now.backendKeys, bk) {
			if err := r.podEgress.Objs.BackendMap.Delete(&bk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				zap.S().Warnf("service: delete stale BackendMap entry: %v", err)
			}
		}
	}
	for _, ak := range old.aclKeys {
		if !containsServiceAclKey(now.aclKeys, ak) {
			if err := r.podEgress.Objs.ServiceAclMap.Delete(&ak); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				zap.S().Warnf("service: delete stale ServiceAclMap entry: %v", err)
			}
		}
	}

	return nil
}

// resolveAllowedConsumerVpcIDs translates the
// shared-service-allowed-consumer-vpcs annotation into the BPF-side
// vpc_id whitelist. Returns hasACL=false when no ACL is configured
// (every consume-enabled Vpc is admitted by default). Vpcs listed in
// the annotation but not yet reconciled (VpcID=0) or absent from the
// cache are skipped silently; the next Vpc event will re-run the
// reconciler and pick them up. The reconciler must list these
// resources via its informer cache so the lookup is O(N_vpcs)
// without an extra round-trip.
func (r *Service) resolveAllowedConsumerVpcIDs(ctx context.Context, svc *corev1.Service) ([]uint32, bool, error) {
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

func (r *Service) delete(key string) error {
	r.mu.Lock()
	old, ok := r.snapshots[key]
	if ok {
		delete(r.snapshots, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	for _, sk := range old.serviceKeys {
		if err := r.podEgress.Objs.ServiceMap.Delete(&sk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("service: delete ServiceMap entry: %v", err)
		}
	}
	for _, bk := range old.backendKeys {
		if err := r.podEgress.Objs.BackendMap.Delete(&bk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("service: delete BackendMap entry: %v", err)
		}
	}
	for _, ak := range old.aclKeys {
		if err := r.podEgress.Objs.ServiceAclMap.Delete(&ak); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("service: delete ServiceAclMap entry: %v", err)
		}
	}
	return nil
}

// FanOutEndpointSliceToService is a keys-func for Runner.WatchFanOut: an
// EndpointSlice change re-enqueues the Service it advertises (the
// "kubernetes.io/service-name" label).
func (r *Service) FanOutEndpointSliceToService(obj any) []string {
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
// signal (e.g. NetworkInterface change) cannot be tied to a single
// Service.
func (r *Service) FanOutAllServices(any) []string {
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

// endpointInfo flattens a single (address, port, targetRef) tuple from an
// EndpointSlice so the reconciler can iterate without nested loops.
type endpointInfo struct {
	address   string
	port      int32
	portName  string
	targetRef *corev1.ObjectReference
}

func (r *Service) collectEndpoints(ctx context.Context, svc *corev1.Service) ([]endpointInfo, error) {
	var sliceList discoveryv1.EndpointSliceList
	selector := labels.SelectorFromSet(labels.Set{kubernetesServiceLabel: svc.Name})
	if err := r.client.List(ctx, &sliceList, client.InNamespace(svc.Namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}

	var out []endpointInfo
	for _, slice := range sliceList.Items {
		if slice.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		for _, ep := range slice.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, addr := range ep.Addresses {
				for _, p := range slice.Ports {
					info := endpointInfo{
						address:   addr,
						port:      portValue(p.Port),
						portName:  portName(p.Name),
						targetRef: ep.TargetRef,
					}
					out = append(out, info)
				}
			}
		}
	}
	return out, nil
}

func (r *Service) findInterfaceForPod(ctx context.Context, namespace, podName string) (*juneauv1alpha1.NetworkInterface, error) {
	var ifaceList juneauv1alpha1.NetworkInterfaceList
	if err := r.client.List(ctx, &ifaceList, client.InNamespace(namespace), client.MatchingFields{"spec.podRef.name": podName}); err != nil {
		return nil, err
	}
	if len(ifaceList.Items) == 0 {
		return nil, nil
	}
	// Prefer a Ready interface but fall back to the first one we find.
	for i := range ifaceList.Items {
		if ifaceList.Items[i].Status.Phase == juneauv1alpha1.NetworkInterfacePhaseReady {
			return &ifaceList.Items[i], nil
		}
	}
	return &ifaceList.Items[0], nil
}

// serviceFlags returns the SVC_FLAG_* bitmask written to service_val.flags
// for the given Service. The shared decision lives in svcpolicy so
// the BPF backend programmer and the virtual DNS resolver answer the
// same question identically; the ACL bit is signalled separately by
// the caller because resolving the ACL list also requires
// per-consumer-Vpc lookups.
func serviceFlags(svc *corev1.Service, hasACL bool) uint32 {
	var flags uint32
	if svcpolicy.IsShared(svc) {
		flags |= svcFlagShared
	}
	if hasACL {
		flags |= svcFlagHasACL
	}
	return flags
}

func matchEndpointsForPort(endpoints []endpointInfo, svcPort corev1.ServicePort) []endpointInfo {
	var matched []endpointInfo
	wantName := svcPort.Name
	for _, ep := range endpoints {
		if wantName == "" || ep.portName == wantName || ep.portName == "" {
			matched = append(matched, ep)
		}
	}
	return matched
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

func portValue(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func portName(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func splitNamespacedKey(key string) (string, string, bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
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
