package reconciler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

type VpcEndpoint struct {
	client    client.Client
	podEgress *program.PodEgress
	mu        sync.Mutex
	snapshots map[string]vpcEndpointSnapshot
}

type vpcEndpointSnapshot struct {
	keys     []bpf.PodEgressVpcEndpointKey
	value    bpf.PodEgressVpcEndpointVal
	arpKey   bpf.PodEgressArpTableKey
	arpValue bpf.PodEgressArpTableVal
}

func NewVpcEndpoint(cl client.Client, podEgress *program.PodEgress) *VpcEndpoint {
	return &VpcEndpoint{client: cl, podEgress: podEgress, snapshots: map[string]vpcEndpointSnapshot{}}
}

func (r *VpcEndpoint) Name() string { return "vpc-endpoint" }

func (r *VpcEndpoint) Reconcile(ctx context.Context, key string) error {
	var endpoint juneauv1alpha1.VpcEndpoint
	if err := r.client.Get(ctx, client.ObjectKey{Name: key}, &endpoint); err != nil {
		if apierrors.IsNotFound(err) {
			return r.delete(key)
		}
		return err
	}
	return r.upsert(ctx, key, &endpoint)
}

func (r *VpcEndpoint) upsert(ctx context.Context, key string, endpoint *juneauv1alpha1.VpcEndpoint) error {
	address := net.ParseIP(endpoint.Status.Address).To4()
	if address == nil {
		return r.delete(key)
	}

	var vpc juneauv1alpha1.Vpc
	if err := r.client.Get(ctx, client.ObjectKey{Name: endpoint.Spec.Vpc}, &vpc); err != nil {
		return err
	}
	if vpc.Status.VpcID == 0 {
		return nil
	}
	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: endpoint.Spec.Subnet}, &subnet); err != nil {
		return err
	}
	gatewayMAC, err := net.ParseMAC(subnet.Status.GatewayMAC)
	if err != nil {
		return fmt.Errorf("parse Subnet gateway MAC: %w", err)
	}
	mac, err := convert.HardwareAddrToUint8Array(gatewayMAC)
	if err != nil {
		return err
	}

	ref := endpoint.Spec.Service
	var service corev1.Service
	if err := r.client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &service); err != nil {
		if apierrors.IsNotFound(err) {
			return r.delete(key)
		}
		return err
	}
	clusterIP := net.ParseIP(service.Spec.ClusterIP).To4()
	if clusterIP == nil {
		return r.delete(key)
	}

	addressHost := binary.BigEndian.Uint32(address)
	desired := vpcEndpointSnapshot{
		value:    bpf.PodEgressVpcEndpointVal{ClusterIp: binary.BigEndian.Uint32(clusterIP)},
		arpKey:   bpf.PodEgressArpTableKey{SubnetId: subnet.Status.VNI, Ipaddr: addressHost},
		arpValue: bpf.PodEgressArpTableVal{Mac: mac},
	}
	for _, port := range service.Spec.Ports {
		proto := vpcEndpointProtocol(port.Protocol)
		if proto == 0 || port.Port < 1 || port.Port > 65535 {
			continue
		}
		desired.keys = append(desired.keys, bpf.PodEgressVpcEndpointKey{VpcId: vpc.Status.VpcID, Address: addressHost, Port: uint16(port.Port), Proto: proto})
	}
	if len(desired.keys) == 0 {
		return r.delete(key)
	}

	r.mu.Lock()
	previous, hadPrevious := r.snapshots[key]
	r.mu.Unlock()
	if err := r.programSnapshot(desired); err != nil {
		_ = r.deleteSnapshot(desired)
		if hadPrevious {
			_ = r.programSnapshot(previous)
		}
		return err
	}
	if hadPrevious {
		if err := r.pruneSnapshot(previous, desired); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.snapshots[key] = desired
	r.mu.Unlock()
	return nil
}

func (r *VpcEndpoint) programSnapshot(snapshot vpcEndpointSnapshot) error {
	for i := range snapshot.keys {
		if err := r.podEgress.Objs.VpcEndpointMap.Update(&snapshot.keys[i], &snapshot.value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update VpcEndpointMap: %w", err)
		}
	}
	if err := r.podEgress.Objs.ArpTable.Update(&snapshot.arpKey, &snapshot.arpValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update endpoint proxy ARP: %w", err)
	}
	return nil
}

func (r *VpcEndpoint) pruneSnapshot(previous, desired vpcEndpointSnapshot) error {
	var result error
	for i := range previous.keys {
		if containsVpcEndpointKey(desired.keys, previous.keys[i]) {
			continue
		}
		if err := r.podEgress.Objs.VpcEndpointMap.Delete(&previous.keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			result = errors.Join(result, err)
		}
	}
	if previous.arpKey != desired.arpKey {
		if err := r.podEgress.Objs.ArpTable.Delete(&previous.arpKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func containsVpcEndpointKey(keys []bpf.PodEgressVpcEndpointKey, target bpf.PodEgressVpcEndpointKey) bool {
	for i := range keys {
		if keys[i] == target {
			return true
		}
	}
	return false
}

func (r *VpcEndpoint) delete(key string) error {
	r.mu.Lock()
	snapshot, ok := r.snapshots[key]
	delete(r.snapshots, key)
	r.mu.Unlock()
	if !ok {
		return nil
	}
	return r.deleteSnapshot(snapshot)
}

func (r *VpcEndpoint) deleteSnapshot(snapshot vpcEndpointSnapshot) error {
	var result error
	for i := range snapshot.keys {
		if err := r.podEgress.Objs.VpcEndpointMap.Delete(&snapshot.keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			result = errors.Join(result, err)
		}
	}
	if err := r.podEgress.Objs.ArpTable.Delete(&snapshot.arpKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		result = errors.Join(result, err)
	}
	return result
}

func vpcEndpointProtocol(protocol corev1.Protocol) uint8 {
	switch protocol {
	case corev1.ProtocolTCP, "":
		return 6
	case corev1.ProtocolUDP:
		return 17
	case corev1.ProtocolSCTP:
		return 132
	default:
		return 0
	}
}

func (r *VpcEndpoint) FanOutAll(any) []string {
	var endpoints juneauv1alpha1.VpcEndpointList
	if err := r.client.List(context.Background(), &endpoints); err != nil {
		return nil
	}
	keys := make([]string, 0, len(endpoints.Items))
	for i := range endpoints.Items {
		keys = append(keys, endpoints.Items[i].Name)
	}
	return keys
}

func (r *VpcEndpoint) FanOutService(obj any) []string {
	service, ok := obj.(*corev1.Service)
	if !ok {
		return nil
	}
	var endpoints juneauv1alpha1.VpcEndpointList
	if err := r.client.List(context.Background(), &endpoints); err != nil {
		return nil
	}
	keys := make([]string, 0)
	for i := range endpoints.Items {
		ref := endpoints.Items[i].Spec.Service
		if ref.Namespace == service.Namespace && ref.Name == service.Name {
			keys = append(keys, endpoints.Items[i].Name)
		}
	}
	return keys
}
