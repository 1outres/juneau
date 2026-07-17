package serviceloadbalancer

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// kubernetesServiceLabel matches the label every EndpointSlice
// carries linking it to its parent Service.
const kubernetesServiceLabel = "kubernetes.io/service-name"

// reconcilerName is used by Runner for log prefixes. Match the kind
// of resource we own to keep the daemon log readable.
const reconcilerName = "serviceloadbalancer"

// Reconciler keeps the userspace LB programming in sync with one
// Juneau-managed ServiceLoadBalancer per Run. The reconciler is
// keyed by namespaced SLB name; fan-outs from Service /
// EndpointSlice / NetworkInterface enqueue the SLB via the deterministic
// SLB-name = Service-name mapping (Phase 2).
type Reconciler struct {
	client     client.Client
	programmer Programmer
	nodeName   string

	mu        sync.Mutex
	snapshots map[string]struct{} // tracks which keys we've ever programmed
}

// NewReconciler constructs the per-node LB reconciler.
func NewReconciler(cl client.Client, programmer Programmer, nodeName string) *Reconciler {
	return &Reconciler{
		client:     cl,
		programmer: programmer,
		nodeName:   nodeName,
		snapshots:  map[string]struct{}{},
	}
}

// Name implements runner.Reconciler.
func (r *Reconciler) Name() string { return reconcilerName }

// Reconcile drives one SLB key towards its desired dataplane state.
// Errors here come from API access (transient) or from invariant
// violations the controller plane should not produce; we return them
// so the workqueue can retry.
func (r *Reconciler) Reconcile(ctx context.Context, key string) error {
	ns, name, ok := splitNamespacedKey(key)
	if !ok {
		return fmt.Errorf("invalid SLB key %q", key)
	}

	var slb juneauv1alpha1.ServiceLoadBalancer
	err := r.client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &slb)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	if !slb.DeletionTimestamp.IsZero() {
		return r.delete(key)
	}
	return r.upsert(ctx, key, &slb)
}

// delete clears any recorded state for the key. Idempotent.
func (r *Reconciler) delete(key string) error {
	if err := r.programmer.Apply(key, nil); err != nil {
		return fmt.Errorf("delete LBService %q: %w", key, err)
	}
	r.forgetSnapshot(key)
	return nil
}

func (r *Reconciler) upsert(ctx context.Context, key string, slb *juneauv1alpha1.ServiceLoadBalancer) error {
	vip := net.ParseIP(strings.TrimSpace(slb.Status.VIP)).To4()
	if vip == nil {
		// VIP not yet allocated. Keep the key in the snapshot so a
		// later transition still triggers a delete; but program no
		// service entry — the dataplane has nothing to do until a
		// VIP exists.
		return r.delete(key)
	}

	svc, err := r.fetchParentService(ctx, slb)
	if err != nil {
		return err
	}
	if svc == nil {
		return r.delete(key)
	}

	ports := buildPortsFromStatus(slb)
	endpoints, err := r.collectLocalEndpoints(ctx, svc)
	if err != nil {
		return err
	}

	backends, err := r.resolveLocalBackends(ctx, ports, endpoints)
	if err != nil {
		return err
	}

	desired := &LBService{
		Key:         key,
		VIP:         vip,
		Ports:       ports,
		Backends:    backends,
		Advertising: containsString(slb.Status.AdvertisingNodes, r.nodeName),
	}

	if err := r.programmer.Apply(key, desired); err != nil {
		return fmt.Errorf("apply LBService %q: %w", key, err)
	}
	r.recordSnapshot(key)
	zap.S().Debugw("LB reconciled",
		"key", key,
		"vip", vip.String(),
		"ports", len(ports),
		"backends", len(backends),
		"advertising", desired.Advertising,
	)
	return nil
}

// fetchParentService loads the Service referenced by the SLB. A
// missing Service is not a transient error: in that state we want to
// purge the dataplane and wait for the SLB to disappear (the
// controller plane handles that).
func (r *Reconciler) fetchParentService(ctx context.Context, slb *juneauv1alpha1.ServiceLoadBalancer) (*corev1.Service, error) {
	name := strings.TrimSpace(slb.Spec.ServiceRef.Name)
	if name == "" {
		return nil, nil
	}
	var svc corev1.Service
	err := r.client.Get(ctx, client.ObjectKey{Namespace: slb.Namespace, Name: name}, &svc)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &svc, nil
}

// buildPortsFromStatus copies the SLB's resolved ports list into our
// canonical type. The controller upstream is responsible for resolving
// string targetPorts; if any TargetPort is still 0 we drop the entry,
// because installing a backend without a destination port is a
// silent traffic blackhole.
func buildPortsFromStatus(slb *juneauv1alpha1.ServiceLoadBalancer) []LBServicePort {
	out := make([]LBServicePort, 0, len(slb.Status.Ports))
	for _, p := range slb.Status.Ports {
		if p.TargetPort == 0 {
			continue
		}
		out = append(out, LBServicePort{
			Name:       p.Name,
			Port:       uint16(p.Port),
			Protocol:   p.Protocol,
			TargetPort: uint16(p.TargetPort),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return string(out[i].Protocol) < string(out[j].Protocol)
	})
	return out
}

// localEndpoint is the per-(slice, endpoint, addr, port) row used by
// the resolver. A single EndpointSlice endpoint can publish multiple
// addresses and (named) ports; we explode them so resolveLocalBackends
// can pair each port to a specific LBServicePort.
type localEndpoint struct {
	address     string
	port        int32
	portName    string
	nodeName    string
	targetRef   *corev1.ObjectReference
	ready       bool
	serving     bool
	terminating bool
}

func (r *Reconciler) collectLocalEndpoints(ctx context.Context, svc *corev1.Service) ([]localEndpoint, error) {
	var sliceList discoveryv1.EndpointSliceList
	selector := labels.SelectorFromSet(labels.Set{kubernetesServiceLabel: svc.Name})
	if err := r.client.List(ctx, &sliceList, client.InNamespace(svc.Namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}

	var out []localEndpoint
	for _, slice := range sliceList.Items {
		if slice.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		for _, ep := range slice.Endpoints {
			ready := condBoolDefault(ep.Conditions.Ready, true)
			serving := condBoolDefault(ep.Conditions.Serving, ready)
			terminating := condBoolDefault(ep.Conditions.Terminating, false)
			if !ready || !serving || terminating {
				continue
			}
			node := ""
			if ep.NodeName != nil {
				node = *ep.NodeName
			}
			// iTP=Local: skip endpoints not on this node.
			if node != r.nodeName {
				continue
			}
			for _, addr := range ep.Addresses {
				if addr == "" {
					continue
				}
				for _, p := range slice.Ports {
					out = append(out, localEndpoint{
						address:     addr,
						port:        portValueOrZero(p.Port),
						portName:    portStringOrEmpty(p.Name),
						nodeName:    node,
						targetRef:   ep.TargetRef,
						ready:       ready,
						serving:     serving,
						terminating: terminating,
					})
				}
			}
		}
	}
	return out, nil
}

// resolveLocalBackends pairs every LBServicePort to the EndpointSlice
// rows it accepts (by name when set, otherwise by integer port) and
// resolves each backend's PodIP to a Juneau Subnet VNI via the
// per-Pod NetworkInterface lookup. Endpoints whose target Pod has no
// NetworkInterface (host-network, foreign workload) are dropped with
// a debug log — the design defers host-network LoadBalancer support
// to a later release.
func (r *Reconciler) resolveLocalBackends(ctx context.Context, ports []LBServicePort, endpoints []localEndpoint) ([]LBBackend, error) {
	var out []LBBackend
	for _, port := range ports {
		matched := matchEndpointsForPort(endpoints, port)
		for _, ep := range matched {
			ip := net.ParseIP(ep.address).To4()
			if ip == nil {
				continue
			}
			subnetID, err := r.resolveSubnetID(ctx, ep)
			if err != nil {
				return nil, err
			}
			if subnetID == 0 {
				zap.S().Debugw("LB: skipping non-Juneau backend (host-network or unresolved Pod)",
					"address", ep.address, "port", ep.port)
				continue
			}
			backend := LBBackend{
				PodIP:       append(net.IP(nil), ip...),
				ServicePort: port.Port,
				TargetPort:  uint16(ep.port),
				Protocol:    port.Protocol,
				SubnetID:    subnetID,
			}
			if ep.targetRef != nil && ep.targetRef.Kind == "Pod" {
				backend.PodNamespace = ep.targetRef.Namespace
				backend.PodName = ep.targetRef.Name
			}
			out = append(out, backend)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServicePort != out[j].ServicePort {
			return out[i].ServicePort < out[j].ServicePort
		}
		if out[i].Protocol != out[j].Protocol {
			return string(out[i].Protocol) < string(out[j].Protocol)
		}
		return out[i].PodIP.String() < out[j].PodIP.String()
	})
	return out, nil
}

// matchEndpointsForPort applies the Service ↔ EndpointSlice port
// matching rules: when the Service port has a Name, the slice must
// have a port with that exact name; otherwise the slice port number
// must match the Service port. This mirrors the daemon's existing
// ClusterIP behaviour and aligns with the b08313e/7265326 fixes.
func matchEndpointsForPort(endpoints []localEndpoint, port LBServicePort) []localEndpoint {
	var out []localEndpoint
	for _, ep := range endpoints {
		if port.Name != "" {
			if ep.portName != port.Name {
				continue
			}
		} else if uint16(ep.port) != port.Port {
			continue
		}
		out = append(out, ep)
	}
	return out
}

// resolveSubnetID looks up the NetworkInterface for the endpoint's
// target Pod (TargetRef Kind=Pod) and consults the Subnet to read the
// allocated VNI. Returns 0 when the Pod is not Juneau-managed.
func (r *Reconciler) resolveSubnetID(ctx context.Context, ep localEndpoint) (uint32, error) {
	if ep.targetRef == nil || ep.targetRef.Kind != "Pod" {
		return 0, nil
	}
	var ifaces juneauv1alpha1.NetworkInterfaceList
	if err := r.client.List(ctx, &ifaces, client.InNamespace(ep.targetRef.Namespace), client.MatchingFields{"spec.podRef.name": ep.targetRef.Name}); err != nil {
		return 0, err
	}
	if len(ifaces.Items) == 0 {
		return 0, nil
	}
	iface := ifaces.Items[0]
	if iface.Spec.Subnet == "" {
		return 0, nil
	}
	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: iface.Spec.Subnet}, &subnet); err != nil {
		if apierrors.IsNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	return subnet.Status.VNI, nil
}

// FanOutServiceToSLB maps a Service event back to the SLB that
// fronts it. The SLB-name = Service-name mapping is the same one
// the controller plane uses (ServiceLoadBalancerNameForService).
func (r *Reconciler) FanOutServiceToSLB(obj any) []string {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return nil
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return nil
	}
	return []string{svc.Namespace + "/" + svc.Name}
}

// FanOutEndpointSliceToSLB maps an EndpointSlice event to the SLB
// for the underlying Service.
func (r *Reconciler) FanOutEndpointSliceToSLB(obj any) []string {
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

// FanOutNetworkInterfaceToSLBs re-enqueues every known SLB when a
// NetworkInterface changes. We don't (yet) have a precise pod →
// SLB index, so we let the reconciler's per-key dedup handle the
// fan-out cost.
func (r *Reconciler) FanOutNetworkInterfaceToSLBs(any) []string {
	r.mu.Lock()
	keys := make([]string, 0, len(r.snapshots))
	for k := range r.snapshots {
		keys = append(keys, k)
	}
	r.mu.Unlock()
	return keys
}

func (r *Reconciler) recordSnapshot(key string) {
	r.mu.Lock()
	r.snapshots[key] = struct{}{}
	r.mu.Unlock()
}

func (r *Reconciler) forgetSnapshot(key string) {
	r.mu.Lock()
	delete(r.snapshots, key)
	r.mu.Unlock()
}

// condBoolDefault returns *cond when set, else def.
func condBoolDefault(cond *bool, def bool) bool {
	if cond == nil {
		return def
	}
	return *cond
}

func portValueOrZero(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func portStringOrEmpty(p *string) string {
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

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
