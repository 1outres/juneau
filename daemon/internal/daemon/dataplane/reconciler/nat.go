package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// Nat keeps podEgress.NatDnatMap and NatSnatMap in sync with
// ElasticIPAttachment objects attached to pods on this node.
type Nat struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu        sync.Mutex
	snapshots map[string]natSnapshot
}

type natSnapshot struct {
	outside bpf.PodEgressNatOutside
	inside  bpf.PodEgressNatInside
}

func NewNat(cl client.Client, podEgress *program.PodEgress, nodeName string) *Nat {
	return &Nat{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
		snapshots: make(map[string]natSnapshot),
	}
}

func (r *Nat) Name() string { return "nat" }

func (r *Nat) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var eipa juneauv1alpha1.ElasticIPAttachment
	err = r.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &eipa)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}

	if !r.shouldProgram(&eipa) {
		return r.delete(key)
	}
	return r.upsert(ctx, key, &eipa)
}

func (r *Nat) shouldProgram(eipa *juneauv1alpha1.ElasticIPAttachment) bool {
	return eipa.DeletionTimestamp == nil &&
		eipa.Status.Phase == juneauv1alpha1.ElasticIPAttachmentPhaseAttached &&
		eipa.Status.ElasticIP != "" &&
		eipa.Status.PodIP != "" &&
		eipa.Status.NodeName == r.nodeName
}

func (r *Nat) upsert(ctx context.Context, key string, eipa *juneauv1alpha1.ElasticIPAttachment) error {
	outside, inside, err := r.resolveNAT(ctx, eipa)
	if err != nil {
		return err
	}
	desired := natSnapshot{outside: outside, inside: inside}

	r.mu.Lock()
	old, hadOld := r.snapshots[key]
	r.mu.Unlock()

	if hadOld && old != desired {
		if err := r.deleteEntries(old); err != nil {
			return err
		}
	}

	if err := r.podEgress.Objs.NatDnatMap.Update(&desired.outside, &desired.inside, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update nat_dnat_map: %w", err)
	}
	if err := r.podEgress.Objs.NatSnatMap.Update(&desired.inside, &desired.outside, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update nat_snat_map: %w", err)
	}

	r.mu.Lock()
	r.snapshots[key] = desired
	r.mu.Unlock()
	return nil
}

func (r *Nat) delete(key string) error {
	r.mu.Lock()
	snap, ok := r.snapshots[key]
	if ok {
		delete(r.snapshots, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	return r.deleteEntries(snap)
}

func (r *Nat) deleteEntries(snap natSnapshot) error {
	if err := r.podEgress.Objs.NatDnatMap.Delete(&snap.outside); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete nat_dnat_map: %w", err)
	}
	if err := r.podEgress.Objs.NatSnatMap.Delete(&snap.inside); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete nat_snat_map: %w", err)
	}
	return nil
}

func (r *Nat) resolveNAT(ctx context.Context, eipa *juneauv1alpha1.ElasticIPAttachment) (bpf.PodEgressNatOutside, bpf.PodEgressNatInside, error) {
	var outside bpf.PodEgressNatOutside
	var inside bpf.PodEgressNatInside

	elasticIP := net.ParseIP(eipa.Status.ElasticIP)
	if elasticIP == nil {
		return outside, inside, fmt.Errorf("failed to parse elastic IP: %s", eipa.Status.ElasticIP)
	}
	outsideAddr, err := convert.IPv4ToUint32(elasticIP)
	if err != nil {
		return outside, inside, err
	}

	podIP := net.ParseIP(eipa.Status.PodIP)
	if podIP == nil {
		return outside, inside, fmt.Errorf("failed to parse pod IP: %s", eipa.Status.PodIP)
	}
	insideAddr, err := convert.IPv4ToUint32(podIP)
	if err != nil {
		return outside, inside, err
	}

	subnetName, err := r.resolveSubnetName(ctx, eipa)
	if err != nil {
		return outside, inside, err
	}

	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
		return outside, inside, err
	}

	outside.Addr = outsideAddr
	inside.SubnetId = subnet.Status.VNI
	inside.Addr = insideAddr
	return outside, inside, nil
}

func (r *Nat) resolveSubnetName(ctx context.Context, eipa *juneauv1alpha1.ElasticIPAttachment) (string, error) {
	var nwif juneauv1alpha1.NetworkInterface
	err := r.client.Get(ctx, client.ObjectKey{Namespace: eipa.Namespace, Name: eipa.Spec.TargetRef.NetworkInterfaceName}, &nwif)
	if err == nil {
		if nwif.Spec.Subnet != "" {
			return nwif.Spec.Subnet, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return "", err
	}

	var nwep juneauv1alpha1.NetworkEndpoint
	if err := r.client.Get(ctx, client.ObjectKey{Namespace: eipa.Namespace, Name: eipa.Spec.TargetRef.NetworkInterfaceName}, &nwep); err != nil {
		return "", err
	}
	if nwep.Spec.Subnet == "" {
		return "", fmt.Errorf("network endpoint %s/%s has empty subnet", nwep.Namespace, nwep.Name)
	}
	return nwep.Spec.Subnet, nil
}
