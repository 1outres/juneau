package service

import (
	"context"
	"encoding/binary"
	"net"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

const (
	// backendSubnetIDUnderlay is the sentinel written into
	// backend_val.backend_subnet_id when an endpoint lives on the
	// underlay (a non-Pod target such as kube-apiserver, or a
	// hostNetwork Pod we don't manage). The BPF data plane treats
	// this value as "host-network NAPT path" rather than "Pod
	// backend with VNI 0".
	backendSubnetIDUnderlay uint32 = 0

	// backend_val.kind constants; mirror BACKEND_KIND_* in
	// daemon/bpf/maps.h. See reconciler.go for why we classify
	// host-network endpoints by IP equality with the daemon's own
	// underlay address rather than by EndpointSlice.nodeName.
	backendKindPod        uint8 = 0
	backendKindHostRemote uint8 = 1
	backendKindHostLocal  uint8 = 2
)

// endpointInfo flattens a single (address, port, conditions) row of an
// EndpointSlice for downstream filters. The locality / conditions
// fields are populated even when the endpoint is unreachable so the
// filter stage can apply graceful-termination rules.
type endpointInfo struct {
	address     string
	port        int32
	portName    string
	targetRef   *corev1.ObjectReference
	nodeName    string // EndpointSlice endpoint.NodeName (iTP=Local match)
	ready       bool
	serving     bool // EndpointConditions.Serving — graceful termination signal
	terminating bool // EndpointConditions.Terminating — Pod is being deleted
}

// resolvedBackend pairs the BPF backend value with the source
// EndpointSlice metadata the filter stage needs (nodeName, conditions).
// One resolvedBackend per (Service port × endpoint) pair.
type resolvedBackend struct {
	port        corev1.ServicePort
	val         bpf.PodEgressBackendVal
	nodeName    string
	ready       bool
	serving     bool
	terminating bool
}

func (r *Reconciler) collectEndpoints(ctx context.Context, svc *corev1.Service) ([]endpointInfo, error) {
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
			ready := condBool(ep.Conditions.Ready, true)
			// Default for Serving / Terminating per EndpointSlice
			// semantics: when the field is unset (older publishers)
			// Serving mirrors Ready, Terminating defaults to false.
			serving := condBool(ep.Conditions.Serving, ready)
			terminating := condBool(ep.Conditions.Terminating, false)
			node := ""
			if ep.NodeName != nil {
				node = *ep.NodeName
			}
			for _, addr := range ep.Addresses {
				for _, p := range slice.Ports {
					out = append(out, endpointInfo{
						address:     addr,
						port:        portValue(p.Port),
						portName:    portName(p.Name),
						targetRef:   ep.TargetRef,
						nodeName:    node,
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

// resolveBackends turns endpoint rows into per-port []resolvedBackend
// suitable for the filter stage. The function performs the Pod →
// NetworkInterface lookup so locality is decided by EndpointSlice
// metadata while VPC scoping is decided by NetworkInterface ownership.
func (r *Reconciler) resolveBackends(ctx context.Context, svc *corev1.Service, vpcName string, endpoints []endpointInfo) (map[corev1.ServicePort][]resolvedBackend, error) {
	out := map[corev1.ServicePort][]resolvedBackend{}
	for _, port := range svc.Spec.Ports {
		matched := matchEndpointsForPort(endpoints, port)
		for _, ep := range matched {
			if ep.address == "" {
				continue
			}
			ip := net.ParseIP(ep.address).To4()
			if ip == nil {
				continue
			}

			var iface *juneauv1alpha1.NetworkInterface
			if ep.targetRef != nil && ep.targetRef.Kind == "Pod" {
				var err error
				iface, err = r.findInterfaceForPod(ctx, ep.targetRef.Namespace, ep.targetRef.Name)
				if err != nil {
					return nil, err
				}
			}

			val := bpf.PodEgressBackendVal{
				BackendIp:   binary.BigEndian.Uint32(ip),
				BackendPort: uint16(ep.port),
			}

			if iface == nil {
				kind := backendKindHostRemote
				if r.nodeIP != nil && ip.Equal(r.nodeIP) {
					kind = backendKindHostLocal
				}
				val.Kind = kind
				val.BackendSubnetId = backendSubnetIDUnderlay
			} else {
				subnetName := iface.Spec.Subnet
				var subnet juneauv1alpha1.Subnet
				if err := r.client.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
					if apierrors.IsNotFound(err) {
						continue
					}
					return nil, err
				}
				if subnet.Spec.Vpc != vpcName {
					// VPC scope enforcement: ignore backends outside the
					// Service's owning VPC.
					continue
				}
				if subnet.Status.VNI == 0 {
					continue
				}
				val.Kind = backendKindPod
				val.BackendSubnetId = subnet.Status.VNI
			}

			out[port] = append(out[port], resolvedBackend{
				port:        port,
				val:         val,
				nodeName:    ep.nodeName,
				ready:       ep.ready,
				serving:     ep.serving,
				terminating: ep.terminating,
			})
		}
	}
	return out, nil
}

func (r *Reconciler) findInterfaceForPod(ctx context.Context, namespace, podName string) (*juneauv1alpha1.NetworkInterface, error) {
	var attachments juneauv1alpha1.NetworkInterfaceAttachmentList
	if err := r.client.List(ctx, &attachments, client.InNamespace(namespace), client.MatchingFields{"spec.podRef.name": podName}); err != nil {
		return nil, err
	}
	if len(attachments.Items) == 0 {
		return nil, nil
	}
	var networkInterface juneauv1alpha1.NetworkInterface
	if err := r.client.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      attachments.Items[0].Spec.NetworkInterfaceRef,
	}, &networkInterface); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &networkInterface, nil
}

// matchEndpointsForPort returns the endpoint rows that backend the
// given Service port. Matching mirrors kube-proxy:
//
//   - svcPort.Name == "" — accept every endpoint regardless of its
//     portName. Upstream validation only allows an unnamed Service
//     port when the Service has a single port, so this cannot collide
//     with another port on the same Service.
//
//   - svcPort.Name is set — accept only endpoints whose portName
//     matches exactly. Endpoints with empty portName are rejected so a
//     manually-managed EndpointSlice with missing port names cannot
//     register a single backend under multiple named Service ports
//     (which would route e.g. metrics traffic to the http container
//     port).
func matchEndpointsForPort(endpoints []endpointInfo, svcPort corev1.ServicePort) []endpointInfo {
	var matched []endpointInfo
	wantName := svcPort.Name
	for _, ep := range endpoints {
		if wantName == "" || ep.portName == wantName {
			matched = append(matched, ep)
		}
	}
	return matched
}

func condBool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
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
