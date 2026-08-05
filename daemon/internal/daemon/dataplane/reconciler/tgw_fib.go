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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// TgwFib keeps podEgress.TgwFibMap in sync with
// TransitGatewayRouteTable objects. It mirrors Fib: each route table
// owns an inner LPM trie, and on update the reconciler builds a fresh
// one, atomically swaps it into TgwFibMap, and closes the old one.
//
// A route table's contents also depend on the Subnets its routes
// resolve to, so Subnet events fan out to re-enqueue every route table
// via FanOutAllTransitGatewayRouteTables. Attachments need no watch of
// their own: the controller republishes status.routes whenever an
// attachment changes.
type TgwFib struct {
	client    client.Client
	podEgress *program.PodEgress

	mu        sync.Mutex
	snapshots map[string]fibSnapshot // route table name -> current inner map
}

func NewTgwFib(cl client.Client, podEgress *program.PodEgress) *TgwFib {
	return &TgwFib{
		client:    cl,
		podEgress: podEgress,
		snapshots: make(map[string]fibSnapshot),
	}
}

func (r *TgwFib) Name() string { return "tgw-fib" }

func (r *TgwFib) Reconcile(ctx context.Context, key string) error {
	var rt juneauv1alpha1.TransitGatewayRouteTable
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &rt)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	return r.upsert(ctx, key, &rt)
}

func (r *TgwFib) upsert(ctx context.Context, key string, rt *juneauv1alpha1.TransitGatewayRouteTable) error {
	// A table ID of 0 means the controller has not allocated one yet.
	// Programming it would claim key 0 of TgwFibMap for a table that
	// will move as soon as the allocation lands, so wait instead.
	if rt.Status.TableID == 0 {
		return nil
	}

	fib, err := ebpf.NewMap(r.podEgress.MapSpecs.TgwFibInner.Copy())
	if err != nil {
		return fmt.Errorf("create new transit FIB inner map: %w", err)
	}
	defer func() {
		if fib != nil {
			_ = fib.Close()
		}
	}()

	for _, route := range rt.Status.Routes {
		if err := r.populateRoute(ctx, fib, &route); err != nil {
			return err
		}
	}

	if err := r.podEgress.Objs.TgwFibMap.Update(rt.Status.TableID, uint32(fib.FD()), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update TgwFibMap for table %d: %w", rt.Status.TableID, err)
	}

	r.mu.Lock()
	old, hadOld := r.snapshots[key]
	r.snapshots[key] = fibSnapshot{tableID: rt.Status.TableID, fib: fib}
	r.mu.Unlock()

	// Outer TgwFibMap now references the new inner map; transfer
	// ownership away from the deferred cleanup.
	fib = nil

	if hadOld && old.tableID != rt.Status.TableID {
		if err := r.podEgress.Objs.TgwFibMap.Delete(old.tableID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("tgw-fib: delete stale TgwFibMap entry %d: %v", old.tableID, err)
		}
	}

	if hadOld && old.fib != nil {
		if err := old.fib.Close(); err != nil {
			zap.S().Warnf("tgw-fib: close old inner map for %s: %v", key, err)
		}
	}

	return nil
}

func (r *TgwFib) delete(key string) error {
	r.mu.Lock()
	old, ok := r.snapshots[key]
	if ok {
		delete(r.snapshots, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	if err := r.podEgress.Objs.TgwFibMap.Delete(old.tableID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete TgwFibMap entry %d: %w", old.tableID, err)
	}
	if old.fib != nil {
		if err := old.fib.Close(); err != nil {
			zap.S().Warnf("tgw-fib: close inner map on delete for %s: %v", key, err)
		}
	}
	return nil
}

func (r *TgwFib) populateRoute(ctx context.Context, fib *ebpf.Map, route *juneauv1alpha1.ResolvedTransitGatewayRoute) error {
	netaddr, ipnet, err := net.ParseCIDR(route.Dst)
	if err != nil {
		zap.S().Warnf("tgw-fib: parse CIDR %s: %v", route.Dst, err)
		return nil
	}

	prefixlen, _ := ipnet.Mask.Size()
	key := bpf.PodEgressFibKey{
		Dst:       binary.LittleEndian.Uint32(netaddr.To4()),
		Prefixlen: uint32(prefixlen),
	}

	val, err := r.buildFibVal(ctx, route)
	if err != nil {
		zap.S().Warnf("tgw-fib: build transit route for %s: %v", route.Dst, err)
		return nil
	}

	if err := fib.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update transit FIB inner map for %s: %w", route.Dst, err)
	}
	return nil
}

// buildFibVal renders one resolved transit route. A blackhole route
// carries nothing but its type; every other route forwards straight to
// the target Subnet, which is why it reuses the connected route value.
// route.Attachment and route.Origin are informational and never change
// what the data plane does.
func (r *TgwFib) buildFibVal(ctx context.Context, route *juneauv1alpha1.ResolvedTransitGatewayRoute) (bpf.PodEgressFibVal, error) {
	if route.Blackhole {
		return bpf.PodEgressFibVal{Type: fibRouteTypeBlackhole}, nil
	}

	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: route.Subnet}, &subnet); err != nil {
		return bpf.PodEgressFibVal{}, err
	}
	return buildConnectedFibVal(&subnet)
}

// CloseAll closes every retained inner map. Called by Manager on
// shutdown.
func (r *TgwFib) CloseAll() error {
	r.mu.Lock()
	snaps := r.snapshots
	r.snapshots = make(map[string]fibSnapshot)
	r.mu.Unlock()

	var errs []error
	for _, snap := range snaps {
		if snap.fib == nil {
			continue
		}
		if err := snap.fib.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FanOutAllTransitGatewayRouteTables is a keys-func for
// Runner.WatchFanOut: returns every TransitGatewayRouteTable's key
// regardless of which object triggered the event. Used to re-enqueue
// all of them when a referenced Subnet changes.
func (r *TgwFib) FanOutAllTransitGatewayRouteTables(any) []string {
	var rts juneauv1alpha1.TransitGatewayRouteTableList
	if err := r.client.List(context.Background(), &rts); err != nil {
		zap.S().Warnf("tgw-fib: list TransitGatewayRouteTables for fan-out: %v", err)
		return nil
	}
	keys := make([]string, 0, len(rts.Items))
	for i := range rts.Items {
		keys = append(keys, rts.Items[i].Name)
	}
	return keys
}
