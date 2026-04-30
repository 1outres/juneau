package reconciler

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// ServiceNAT mirrors the local Node's ServiceNATAttachment.assignedIP
// into the service_nat_ip BPF map so pod_egress.handle_service_shared
// can stamp shared-Service flows with this Node's SNAT source IP.
//
// The map is a single-entry array, so the reconciler simply overwrites
// slot 0 on every Reconcile. Other Nodes' attachments are ignored.
type ServiceNAT struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu        sync.Mutex
	installed bool
}

func NewServiceNAT(cl client.Client, podEgress *program.PodEgress, nodeName string) *ServiceNAT {
	return &ServiceNAT{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
	}
}

func (r *ServiceNAT) Name() string { return "service_nat" }

func (r *ServiceNAT) Reconcile(ctx context.Context, key string) error {
	var attachment juneauv1alpha1.ServiceNATAttachment
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &attachment)
	if apierrors.IsNotFound(err) {
		return r.clear(key)
	}
	if err != nil {
		return err
	}

	if attachment.Spec.NodeName != r.nodeName {
		// Not for this Node; clear any stale local entry that the
		// reconciler may have written for the same key earlier (the
		// attachment name is the Node name, so this normally never
		// happens — but the guard keeps the map authoritative).
		return r.clear(key)
	}

	address := strings.TrimSpace(attachment.Status.AssignedIP)
	if address == "" {
		return r.clear(key)
	}

	parsed := net.ParseIP(address)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("invalid assignedIP %q on ServiceNATAttachment %q", address, key)
	}
	hostIP, err := convert.IPv4ToBPFNetworkOrder(parsed)
	if err != nil {
		return fmt.Errorf("parse assignedIP %q: %w", address, err)
	}

	if err := r.podEgress.Objs.ServiceNatIp.Update(uint32(0), hostIP, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update service_nat_ip: %w", err)
	}

	r.mu.Lock()
	r.installed = true
	r.mu.Unlock()
	return nil
}

func (r *ServiceNAT) clear(_ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.installed {
		return nil
	}
	// service_nat_ip is a single-entry ARRAY map, so we cannot delete
	// the slot — overwrite with 0, which the BPF-side check treats as
	// "no SNAT IP available" and drops shared-Service traffic.
	if err := r.podEgress.Objs.ServiceNatIp.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear service_nat_ip: %w", err)
	}
	r.installed = false
	return nil
}

// CloseAll resets the BPF map to 0 on shutdown so traffic doesn't get
// stamped with a stale source IP if the daemon restarts before the
// reconciler converges.
func (r *ServiceNAT) CloseAll() error {
	return r.clear("")
}
