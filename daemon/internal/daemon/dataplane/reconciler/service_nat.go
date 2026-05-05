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

// ServiceNAT mirrors every local-Node ServiceNATAttachment into the
// service_nat_ip BPF map, keyed by the provider Vpc id, so
// pod_egress.handle_service_shared can stamp shared-Service flows
// with the right SNAT source IP for the Service's owner Vpc.
//
// One Node hosts at most one attachment per provider Vpc (the
// VpcReconciler enforces the (Node, Vpc) uniqueness via metadata.name);
// the BPF HASH map can therefore carry one entry per provider Vpc.
// The reconciler tracks the set of provider Vpc ids it has installed
// so it can cleanly delete entries when an attachment is removed or
// its provider Vpc is no longer configured.
type ServiceNAT struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu        sync.Mutex
	installed map[uint32]struct{} // provider vpc_id -> installed
}

func NewServiceNAT(cl client.Client, podEgress *program.PodEgress, nodeName string) *ServiceNAT {
	return &ServiceNAT{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
		installed: map[uint32]struct{}{},
	}
}

func (r *ServiceNAT) Name() string { return "service_nat" }

// natAction enumerates the possible reactions to a
// ServiceNATAttachment event. Decoupling the decision from the side
// effect lets planAction be unit-tested without touching the eBPF map.
type natAction uint8

const (
	natNoop natAction = iota
	natWrite
	natClear
)

// natPlan is the resolved decision planAction returns to Reconcile.
// vpcID is meaningful for natWrite/natClear; address only for
// natWrite. installedKey records the previously-installed vpc_id (if
// any) so a write that targets a different key can also drop the
// stale slot.
type natPlan struct {
	action      natAction
	vpcID       uint32
	address     string
	installedAt uint32
}

// planAction decides what to do with an incoming reconcile event.
//
// The shared informer delivers events for every Node's
// ServiceNATAttachment, but each daemon only owns the slot keyed by
// the local Node. Events for other Nodes are completely irrelevant
// and must be a no-op.
//
// When the event IS for our Node, we map spec.vpc → vpc_id via the
// supplied lookup (the Vpc cache). The lookup may report unknownVpc
// when the Vpc has not yet been reconciled: in that case we keep the
// slot installed (if any) and let the next Vpc event re-trigger the
// reconcile. The same caution applies when the Vpc has VpcID=0.
func planAction(
	key, ourNode string,
	attachment *juneauv1alpha1.ServiceNATAttachment,
	notFound bool,
	vpcID uint32,
	vpcResolved bool,
) (natPlan, error) {
	if notFound {
		return natPlan{action: natClear, vpcID: 0}, nil
	}
	if attachment.Spec.NodeName != ourNode {
		return natPlan{action: natNoop}, nil
	}
	address := strings.TrimSpace(attachment.Status.AssignedIP)
	if address == "" {
		// Controller has not yet allocated; clear the slot we may
		// have installed earlier so we don't leave stale state if
		// the attachment moved Vpcs.
		return natPlan{action: natClear, vpcID: vpcID}, nil
	}
	if !vpcResolved || vpcID == 0 {
		// Provider Vpc not yet known. Hold the existing entry (if
		// any) and let a Vpc event re-fire the reconcile.
		return natPlan{action: natNoop}, nil
	}
	parsed := net.ParseIP(address)
	if parsed == nil || parsed.To4() == nil {
		return natPlan{}, fmt.Errorf("invalid assignedIP %q on ServiceNATAttachment %q", address, key)
	}
	return natPlan{action: natWrite, vpcID: vpcID, address: address}, nil
}

func (r *ServiceNAT) Reconcile(ctx context.Context, key string) error {
	var attachment juneauv1alpha1.ServiceNATAttachment
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &attachment)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return err
	}

	var (
		vpcID       uint32
		vpcResolved bool
	)
	if !notFound && attachment.Spec.Vpc != "" {
		var vpc juneauv1alpha1.Vpc
		if vpcErr := r.client.Get(ctx, client.ObjectKey{Name: attachment.Spec.Vpc}, &vpc); vpcErr == nil {
			vpcID = vpc.Status.VpcID
			vpcResolved = true
		} else if !apierrors.IsNotFound(vpcErr) {
			return vpcErr
		}
	}

	plan, err := planAction(key, r.nodeName, &attachment, notFound, vpcID, vpcResolved)
	if err != nil {
		return err
	}

	switch plan.action {
	case natNoop:
		return nil
	case natClear:
		return r.clearForKey(key, plan.vpcID)
	case natWrite:
		return r.write(plan.vpcID, plan.address)
	}
	return nil
}

// write installs the SNAT IP for the given provider Vpc, replacing
// the previous entry for that key if any.
func (r *ServiceNAT) write(vpcID uint32, address string) error {
	hostIP, err := convert.IPv4ToBPFNetworkOrder(net.ParseIP(address))
	if err != nil {
		return fmt.Errorf("parse assignedIP %q: %w", address, err)
	}
	if err := r.podEgress.Objs.ServiceNatIp.Update(vpcID, hostIP, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update service_nat_ip[%d]: %w", vpcID, err)
	}
	r.mu.Lock()
	r.installed[vpcID] = struct{}{}
	r.mu.Unlock()
	return nil
}

// clearForKey removes the slot for vpcID. When vpcID is 0 (the Vpc
// for the deleted attachment is not known) we have no slot to clear,
// because we never installed one. The map_delete is idempotent.
func (r *ServiceNAT) clearForKey(_ string, vpcID uint32) error {
	if vpcID == 0 {
		return nil
	}
	r.mu.Lock()
	_, present := r.installed[vpcID]
	r.mu.Unlock()
	if !present {
		return nil
	}
	if err := r.podEgress.Objs.ServiceNatIp.Delete(vpcID); err != nil && err != ebpf.ErrKeyNotExist {
		return fmt.Errorf("delete service_nat_ip[%d]: %w", vpcID, err)
	}
	r.mu.Lock()
	delete(r.installed, vpcID)
	r.mu.Unlock()
	return nil
}

// CloseAll resets every installed slot to absent on shutdown so
// traffic doesn't get stamped with a stale source IP if the daemon
// restarts before the reconciler converges.
func (r *ServiceNAT) CloseAll() error {
	r.mu.Lock()
	keys := make([]uint32, 0, len(r.installed))
	for k := range r.installed {
		keys = append(keys, k)
	}
	r.installed = map[uint32]struct{}{}
	r.mu.Unlock()
	var firstErr error
	for _, k := range keys {
		if err := r.podEgress.Objs.ServiceNatIp.Delete(k); err != nil && err != ebpf.ErrKeyNotExist && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// FanOutVpcToAttachments enqueues every ServiceNATAttachment whose
// spec.vpc names the changed Vpc. Used by the Runner so a flip of
// Vpc.Status.VpcID propagates without needing a separate watcher.
func (r *ServiceNAT) FanOutVpcToAttachments(obj any) []string {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}
	var list juneauv1alpha1.ServiceNATAttachmentList
	if err := r.client.List(context.Background(), &list); err != nil {
		return nil
	}
	keys := make([]string, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.Vpc == vpc.Name {
			keys = append(keys, list.Items[i].Name)
		}
	}
	return keys
}
