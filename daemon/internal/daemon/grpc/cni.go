package grpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"syscall"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"github.com/containernetworking/cni/pkg/types"
	types040 "github.com/containernetworking/cni/pkg/types/040"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	PodNameKey      = "K8S_POD_NAME"
	PodNamespaceKey = "K8S_POD_NAMESPACE"
	PodUIDKey       = "K8S_POD_UID"
)

// CNIServer keeps two clients on purpose.
//
// cachedClient reads through the daemon's informer cache, which is fine
// for the NetworkInterface an ADD or CHECK needs: the controller writes
// it once and the daemon only waits for it.
//
// apiClient talks to the API server directly. The NetworkEndpoint of a
// pod carries the sandbox generation that tells a stale DEL from a live
// one, and the cache can still hold the generation an ADD has already
// replaced. Deciding on that view would delete a running endpoint, so
// every NetworkEndpoint read that guards a write goes through apiClient.
type CNIServer struct {
	cnipb.UnimplementedCNIServer

	cachedClient   client.Client
	apiClient      client.Client
	probeRegistrar ProbeRegistrar
}

type ProbeRegistrar interface {
	RegisterPod(ctx context.Context, namespace, name, uid, containerID, netnsPath, address string) error
	UnregisterPod(uid, containerID string) error
}

func (c *CNIServer) Add(ctx context.Context, req *cnipb.CNIRequest) (resp *cnipb.CNIResponse, retErr error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]
	podUID := req.Args[PodUIDKey]

	zap.S().Infof("CNI ADD request for pod %s/%s ifname=%s", podNamespace, podName, req.Ifname)
	zap.S().Debugf("CNI ADD request args: %v", req.Args)

	// rollback stack: each cleanup undoes one side effect. Executed in
	// reverse order only when Add returns an error.
	var cleanups []func()
	defer func() {
		if retErr == nil {
			return
		}
		zap.S().Warnf("CNI ADD failed for pod %s/%s, rolling back: %v", podNamespace, podName, retErr)
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()

	var nwifaceList juneauv1alpha1.NetworkInterfaceList
	if err := c.cachedClient.List(ctx, &nwifaceList, client.InNamespace(podNamespace), client.MatchingFields{
		"spec.podRef.uid":       podUID,
		"spec.podRef.name":      podName,
		"spec.podRef.interface": req.Ifname,
	}); err != nil {
		zap.L().Error("failed to list NetworkInterface resources", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to list NetworkInterface resources", err.Error())
	}

	if len(nwifaceList.Items) == 0 {
		zap.L().Error("no NetworkInterface resource found for pod/interface")
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "No NetworkInterface resource found for pod/interface", "")
	}

	nwiface := &nwifaceList.Items[0]

	if meta.IsStatusConditionFalse(nwiface.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusAllocated) {
		zap.L().Error("NetworkInterface resource is not yet allocated")
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "NetworkInterface resource is not yet allocated", "")
	}

	vethHostName := c.vethHostName(req.Ifname, req.ContainerId)
	vethPeerName := c.vethPeerName(req.Ifname, req.ContainerId)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: vethHostName,
		},
		PeerName: vethPeerName,
	}
	if err := c.createVethPair(veth); err != nil {
		zap.L().Error("failed to create veth pair", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to create veth pair", err.Error())
	}
	cleanups = append(cleanups, func() { c.cleanupVeth(vethHostName) })

	zap.S().Debugf("Created veth pair: %s <-> %s", vethHostName, vethPeerName)

	vethHostTmp, err := netlink.LinkByName(vethHostName)
	if err != nil {
		zap.L().Error("failed to lookup created veth", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to lookup created veth", err.Error())
	}

	vethHost, ok := vethHostTmp.(*netlink.Veth)
	if !ok {
		zap.L().Error("failed to cast veth host link", zap.String("linkType", reflect.TypeOf(vethHostTmp).String()))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to cast veth host link", "")
	}

	vethPeerTmp, err := netlink.LinkByName(vethPeerName)
	if err != nil {
		zap.L().Error("failed to lookup created veth", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to lookup created veth", err.Error())
	}

	vethPeer, ok := vethPeerTmp.(*netlink.Veth)
	if !ok {
		zap.L().Error("failed to cast veth peer link", zap.String("linkType", reflect.TypeOf(vethPeerTmp).String()))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to cast veth peer link", "")
	}

	if err := netlink.LinkSetUp(vethHost); err != nil {
		zap.L().Error("failed to bring up veth on host", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to bring up veth on host", err.Error())
	}

	// log req.Netns and req.Path
	zap.S().Debugf("Netns: %s, Path: %s", req.Netns, req.Path)

	netns, err := ns.GetNS(req.Netns)
	if err != nil {
		zap.L().Error("failed to open netns", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to open netns", err.Error())
	}
	defer func() {
		_ = netns.Close()
	}()

	if err := netlink.LinkSetNsFd(vethPeer, int(netns.Fd())); err != nil {
		zap.L().Error("failed to move peer veth to netns", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to move peer veth to netns", err.Error())
	}

	var peerHWAddr net.HardwareAddr
	if err = netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(vethPeerName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetName(link, req.Ifname); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		refreshed, err := netlink.LinkByName(req.Ifname)
		if err != nil {
			return fmt.Errorf("re-lookup peer veth after rename: %w", err)
		}
		peerHWAddr = refreshed.Attrs().HardwareAddr
		return nil
	}); err != nil {
		zap.L().Error("failed to setup veth in netns", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to setup veth in netns", err.Error())
	}

	ip, ipnet, err := net.ParseCIDR(nwiface.Status.Address)
	if err != nil {
		zap.L().Error("failed to parse assigned IP address", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to parse assigned IP address", err.Error())
	}

	type Route struct {
		dst *net.IPNet
		gw  net.IP
	}
	routes := make([]Route, 0, len(nwiface.Status.Routes))

	for _, route := range nwiface.Status.Routes {
		_, dst, err := net.ParseCIDR(route.Dst)
		if err != nil {
			zap.L().Error("failed to parse route destination CIDR", zap.Error(err))
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to parse route destination CIDR", err.Error())
		}
		gw := net.ParseIP(route.GW)
		if gw == nil {
			zap.L().Error("failed to parse route gateway IP", zap.Error(err))
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to parse route gateway IP", "")
		}

		routes = append(routes, Route{dst: dst, gw: gw})
	}

	if err = netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(req.Ifname)
		if err != nil {
			return fmt.Errorf("failed to find interface %s in netns: %w", req.Ifname, err)
		}

		if err := netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ip,
				Mask: ipnet.Mask,
			},
		}); err != nil {
			return fmt.Errorf("failed to assign IP address to interface %s in netns: %w", req.Ifname, err)
		}
		zap.S().Debugf("Assigned IP %s to interface %s in netns", nwiface.Status.Address, req.Ifname)

		for _, route := range routes {
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Gw:        route.gw,
				Dst:       route.dst,
			}); err != nil {
				return fmt.Errorf("failed to add route to interface %s in netns: %w", req.Ifname, err)
			}
		}

		return nil
	}); err != nil {
		zap.L().Error("failed to configure interface in netns", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to configure interface in netns", err.Error())
	}

	hostRefreshed, err := netlink.LinkByIndex(vethHost.Index)
	if err != nil {
		zap.L().Error("failed to re-lookup host veth", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to re-lookup host veth", err.Error())
	}
	hostHWAddr := hostRefreshed.Attrs().HardwareAddr

	nwep := &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: podNamespace,
			Name:      networkEndpointName(podName, req.Ifname),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: juneauv1alpha1.GroupVersion.String(),
					Kind:       "NetworkInterface",
					Name:       nwiface.Name,
					UID:        nwiface.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind: juneauv1alpha1.EndpointKindPod,
			PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
				Name:      podName,
				Interface: req.Ifname,
				UID:       podUID,
			},
			NodeName:   nwiface.Spec.NodeName,
			Subnet:     nwiface.Spec.Subnet,
			Address:    nwiface.Status.Address,
			MACAddress: peerHWAddr.String(),
			Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
				Ifindex:        vethHost.Index,
				HostMACAddress: hostHWAddr.String(),
				ContainerID:    req.ContainerId,
			},
		},
		Status: juneauv1alpha1.NetworkEndpointStatus{},
	}

	createdByUs, err := c.upsertNetworkEndpoint(ctx, nwep, podUID)
	if err != nil {
		zap.L().Error("failed to create NetworkEndpoint resource", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to create NetworkEndpoint resource", err.Error())
	}
	if createdByUs {
		cleanups = append(cleanups, func() { c.cleanupNetworkEndpoint(nwep) })
	}

	res := &types040.Result{
		CNIVersion: "0.4.0",
		Interfaces: []*types040.Interface{
			{
				Name:    req.Ifname,
				Sandbox: req.Netns,
			},
		},
		IPs: []*types040.IPConfig{
			{
				Version:   "4",
				Interface: ptr.To(0),
				Address: net.IPNet{
					IP:   ip,
					Mask: ipnet.Mask,
				},
			},
		},
		Routes: []*types.Route{},
	}

	for _, route := range routes {
		res.Routes = append(res.Routes, &types.Route{
			Dst: *route.dst,
			GW:  route.gw,
		})
	}

	var buf bytes.Buffer
	if err := res.PrintTo(&buf); err != nil {
		zap.L().Error("failed to serialize CNI result", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to serialize CNI result", err.Error())
	}
	if c.probeRegistrar != nil && req.Ifname == "eth0" {
		if err := c.probeRegistrar.RegisterPod(ctx, podNamespace, podName, podUID, req.ContainerId, req.Netns, nwiface.Status.Address); err != nil {
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to register Pod probes", err.Error())
		}
		cleanups = append(cleanups, func() { _ = c.probeRegistrar.UnregisterPod(podUID, req.ContainerId) })
	}

	return &cnipb.CNIResponse{
		ResultJson: buf.Bytes(),
	}, nil
}

func (c *CNIServer) Check(ctx context.Context, req *cnipb.CNIRequest) (*emptypb.Empty, error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]
	podUID := req.Args[PodUIDKey]

	zap.S().Infof("CNI CHECK request for pod %s/%s ifname=%s", podNamespace, podName, req.Ifname)

	// 1. NetworkInterface exists and has been allocated.
	var nwifList juneauv1alpha1.NetworkInterfaceList
	if err := c.cachedClient.List(ctx, &nwifList, client.InNamespace(podNamespace), client.MatchingFields{
		"spec.podRef.uid":       podUID,
		"spec.podRef.name":      podName,
		"spec.podRef.interface": req.Ifname,
	}); err != nil {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to list NetworkInterface resources", err.Error())
	}
	if len(nwifList.Items) == 0 {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "NetworkInterface not found for pod/interface", "")
	}
	nwif := &nwifList.Items[0]
	if meta.IsStatusConditionFalse(nwif.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusAllocated) {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "NetworkInterface is not yet allocated", "")
	}

	// 2. NetworkEndpoint exists and its address agrees with the NWIF.
	var nwepList juneauv1alpha1.NetworkEndpointList
	if err := c.cachedClient.List(ctx, &nwepList, client.InNamespace(podNamespace), client.MatchingFields{
		"spec.podRef.uid":       podUID,
		"spec.podRef.name":      podName,
		"spec.podRef.interface": req.Ifname,
	}); err != nil {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to list NetworkEndpoint resources", err.Error())
	}
	if len(nwepList.Items) == 0 {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "NetworkEndpoint not found for pod/interface", "")
	}
	nwep := &nwepList.Items[0]
	if nwep.Spec.Address != nwif.Status.Address {
		return nil, makeError(cnipb.ErrorCode_INTERNAL,
			"NetworkEndpoint address disagrees with NetworkInterface",
			fmt.Sprintf("nwep=%s nwif=%s", nwep.Spec.Address, nwif.Status.Address))
	}

	// 3. Host-side veth for this container exists.
	vethHostName := c.vethHostName(req.Ifname, req.ContainerId)
	if _, err := netlink.LinkByName(vethHostName); err != nil {
		if _, notFound := err.(netlink.LinkNotFoundError); notFound {
			return nil, makeError(cnipb.ErrorCode_INTERNAL, "host-side veth missing", vethHostName)
		}
		return nil, makeError(cnipb.ErrorCode_INTERNAL, "Failed to lookup host-side veth", err.Error())
	}

	// 4. Pod netns still has the expected interface with the expected IP.
	if err := c.verifyPodInterface(req.Netns, req.Ifname, nwif.Status.Address); err != nil {
		return nil, err
	}

	zap.S().Debugf("CNI CHECK succeeded for pod %s/%s ifname=%s", podNamespace, podName, req.Ifname)
	return &emptypb.Empty{}, nil
}

// verifyPodInterface enters the pod netns and checks that the named
// interface exists and has the expected IPv4 address. Errors are already
// shaped as gRPC status errors with a cnipb.CNIError detail.
func (c *CNIServer) verifyPodInterface(netnsPath, ifname, expectedAddress string) error {
	wantIP, _, err := net.ParseCIDR(expectedAddress)
	if err != nil {
		return makeError(cnipb.ErrorCode_INTERNAL, "Failed to parse NetworkInterface address", err.Error())
	}

	netns, err := ns.GetNS(netnsPath)
	if err != nil {
		return makeError(cnipb.ErrorCode_UNKNOWN_CONTAINER, "Failed to open pod netns", err.Error())
	}
	defer func() { _ = netns.Close() }()

	if err := netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("interface %s not found in netns: %w", ifname, err)
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("list addresses on %s: %w", ifname, err)
		}
		for _, a := range addrs {
			if a.IP.Equal(wantIP) {
				return nil
			}
		}
		return fmt.Errorf("expected IP %s not present on %s", wantIP, ifname)
	}); err != nil {
		return makeError(cnipb.ErrorCode_INTERNAL, "Pod interface verification failed", err.Error())
	}
	return nil
}

func (c *CNIServer) Del(ctx context.Context, req *cnipb.CNIRequest) (*emptypb.Empty, error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]
	podUID := req.Args[PodUIDKey]

	zap.S().Infof("CNI DEL request for pod %s/%s ifname=%s", podNamespace, podName, req.Ifname)

	vethHostName := c.vethHostName(req.Ifname, req.ContainerId)

	vethHost, err := netlink.LinkByName(vethHostName)
	if _, notFoundError := err.(netlink.LinkNotFoundError); !notFoundError && err != nil {
		zap.L().Error("failed to find veth", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to find veth", err.Error())
	} else if !notFoundError {
		if err := netlink.LinkDel(vethHost); err != nil {
			zap.L().Error("failed to delete veth", zap.Error(err))
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to delete veth", err.Error())
		}
		zap.S().Debugf("Deleted veth: %s", vethHostName)
	}

	release, err := c.releaseNetworkEndpoint(ctx, podNamespace, podName, podUID, req.Ifname, req.ContainerId)
	if err != nil {
		zap.L().Error("failed to release NetworkEndpoint resource", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to release NetworkEndpoint resource", err.Error())
	}
	if release == networkEndpointSuperseded {
		zap.S().Debugf("CNI DEL for pod %s/%s ifname=%s ignored: a newer sandbox than container %q owns the endpoint",
			podNamespace, podName, req.Ifname, req.ContainerId)
		return &emptypb.Empty{}, nil
	}

	// Unregister Pod probes only for the generation being torn down. The
	// stale-DEL guard above already ensures this DEL matches the live
	// attachment, so the probe generation is safe to release.
	if c.probeRegistrar != nil && req.Ifname == "eth0" {
		if err := c.probeRegistrar.UnregisterPod(podUID, req.ContainerId); err != nil {
			zap.L().Warn("failed to unregister Pod probes", zap.Error(err))
		}
	}
	return &emptypb.Empty{}, nil
}

// networkEndpointRelease says what a CNI DEL found when it went for the
// Pod NetworkEndpoint of its own sandbox.
type networkEndpointRelease int

const (
	// networkEndpointReleased means no endpoint of this sandbox is left:
	// either the DEL deleted it, or none belonged to the request.
	networkEndpointReleased networkEndpointRelease = iota
	// networkEndpointSuperseded means a newer sandbox owns the endpoint,
	// so the DEL is stale and has to leave the live attachment alone.
	networkEndpointSuperseded
)

// releaseNetworkEndpoint deletes the Pod NetworkEndpoint of the sandbox
// this CNI DEL is for, and only that one.
//
// A sandbox can be recreated under the same Pod UID, so a late DEL from
// the old sandbox can arrive after the new one has taken the endpoint
// over. The read is uncached and the delete is guarded by the version it
// read, so a generation that changed at either point leaves the live
// endpoint standing instead of tearing the running pod off the network.
func (c *CNIServer) releaseNetworkEndpoint(ctx context.Context, namespace, podName, podUID, ifname, containerID string) (networkEndpointRelease, error) {
	key := client.ObjectKey{Namespace: namespace, Name: networkEndpointName(podName, ifname)}

	var nwep juneauv1alpha1.NetworkEndpoint
	if err := c.apiClient.Get(ctx, key, &nwep); err != nil {
		if apierrors.IsNotFound(err) {
			return networkEndpointReleased, nil
		}
		return networkEndpointReleased, fmt.Errorf("fetch NetworkEndpoint %s: %w", key, err)
	}

	if !podRefMatches(nwep.Spec.PodRef, podName, podUID, ifname) {
		// The name belongs to another pod instance, so this DEL has no
		// endpoint of its own to remove.
		return networkEndpointReleased, nil
	}
	if !attachmentBelongsTo(nwep.Spec.Attachment, containerID) {
		return networkEndpointSuperseded, nil
	}

	err := c.apiClient.Delete(ctx, &nwep, client.Preconditions{
		UID:             &nwep.UID,
		ResourceVersion: &nwep.ResourceVersion,
	})
	switch {
	case err == nil, apierrors.IsNotFound(err):
		return networkEndpointReleased, nil
	case apierrors.IsConflict(err):
		return networkEndpointSuperseded, nil
	default:
		return networkEndpointReleased, fmt.Errorf("delete NetworkEndpoint %s: %w", key, err)
	}
}

// networkEndpointName is the name Add gives the NetworkEndpoint of a pod
// interface. Del looks the object up by that name, so both sides have to
// build it the same way.
func networkEndpointName(podName, ifname string) string {
	return podName + "." + ifname
}

func podRefMatches(ref *juneauv1alpha1.NetworkEndpointPodReference, podName, podUID, ifname string) bool {
	return ref != nil && ref.Name == podName && ref.UID == podUID && ref.Interface == ifname
}

// attachmentBelongsTo reports whether the attachment was recorded by the
// given CNI container. Attachments written before the container ID was
// recorded carry an empty one; treat those as legacy and let DEL take
// them down so an upgrade does not leak endpoints.
func attachmentBelongsTo(attachment *juneauv1alpha1.NetworkEndpointAttachment, containerID string) bool {
	return attachment == nil || attachment.ContainerID == "" || attachment.ContainerID == containerID
}

func newCNIServer(cachedClient, apiClient client.Client, probeRegistrar ProbeRegistrar) *CNIServer {
	return &CNIServer{
		cachedClient:   cachedClient,
		apiClient:      apiClient,
		probeRegistrar: probeRegistrar,
	}
}

func makeError(code cnipb.ErrorCode, msg string, details string) error {
	st := status.New(codes.Unknown, msg)

	st, err := st.WithDetails(&cnipb.CNIError{
		Code:    code,
		Msg:     msg,
		Details: details,
	})
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return st.Err()
}

func (c *CNIServer) vethHostName(ifName, containerID string) string {
	return ifName + "+" + containerID[0:10]
}

func (c *CNIServer) vethPeerName(ifName, containerID string) string {
	return "tmp+" + ifName + "+" + containerID[0:6]
}

// createVethPair creates the veth pair. On EEXIST (stale veth from an
// earlier failed ADD with the same container ID + ifname) it deletes the
// existing link and retries once.
func (c *CNIServer) createVethPair(veth *netlink.Veth) error {
	err := netlink.LinkAdd(veth)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) && !errors.Is(err, syscall.EEXIST) {
		return err
	}

	zap.S().Warnf("veth %s already exists; removing stale link and retrying", veth.Name)
	stale, lookupErr := netlink.LinkByName(veth.Name)
	if lookupErr == nil {
		if delErr := netlink.LinkDel(stale); delErr != nil {
			return fmt.Errorf("remove stale veth %s: %w", veth.Name, delErr)
		}
	} else if _, notFound := lookupErr.(netlink.LinkNotFoundError); !notFound {
		return fmt.Errorf("lookup stale veth %s: %w", veth.Name, lookupErr)
	}

	return netlink.LinkAdd(veth)
}

// upsertNetworkEndpoint creates the NetworkEndpoint resource, or when a
// record with the same key already exists (e.g. ADD retried after a crash
// or a sandbox recreation with the same Pod UID) refreshes its attachment
// generation in place. Identity fields (kind, nodeName, subnet, address,
// podRef) are immutable and describe who the endpoint is. MACAddress and
// Attachment (ifindex, host MAC, CNI container ID) belong to the sandbox
// generation and are refreshed together. A UID mismatch indicates a stale
// record for a different pod and is reported as a hard error.
//
// A concurrent DEL of the previous sandbox can remove the record between
// the create and the read, and a concurrent write can move it between the
// read and the update. Both are races over the same key rather than
// faults, so each attempt starts from the desired object again and the
// loop is bounded by the shared retry backoff.
//
// Returns createdByUs=true only when this call actually inserted the
// resource, so the caller knows whether to register a rollback cleanup.
func (c *CNIServer) upsertNetworkEndpoint(ctx context.Context, nwep *juneauv1alpha1.NetworkEndpoint, podUID string) (bool, error) {
	desired := nwep.DeepCopy()

	var createdByUs bool
	err := retry.OnError(retry.DefaultRetry, isNetworkEndpointRace, func() error {
		attempt := desired.DeepCopy()
		created, err := c.createOrRefreshNetworkEndpoint(ctx, attempt, podUID)
		if err != nil {
			return err
		}
		createdByUs = created
		*nwep = *attempt
		return nil
	})
	if err != nil {
		return false, err
	}
	return createdByUs, nil
}

// createOrRefreshNetworkEndpoint is one attempt of upsertNetworkEndpoint.
// It reports whether the attempt inserted the resource.
func (c *CNIServer) createOrRefreshNetworkEndpoint(ctx context.Context, nwep *juneauv1alpha1.NetworkEndpoint, podUID string) (bool, error) {
	err := c.apiClient.Create(ctx, nwep)
	if err == nil {
		return true, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return false, err
	}

	existing := &juneauv1alpha1.NetworkEndpoint{}
	if getErr := c.apiClient.Get(ctx, client.ObjectKeyFromObject(nwep), existing); getErr != nil {
		return false, fmt.Errorf("fetch existing NetworkEndpoint %s/%s: %w", nwep.Namespace, nwep.Name, getErr)
	}
	if existing.Spec.PodRef == nil || existing.Spec.PodRef.UID != podUID {
		var existingUID string
		if existing.Spec.PodRef != nil {
			existingUID = existing.Spec.PodRef.UID
		}
		return false, fmt.Errorf("NetworkEndpoint %s/%s exists for pod UID %q but ADD is for UID %q",
			existing.Namespace, existing.Name, existingUID, podUID)
	}

	// Same pod instance: refresh the attachment generation (pod MAC,
	// ifindex, host MAC, CNI container ID) to match the new sandbox.
	existing.Spec.MACAddress = nwep.Spec.MACAddress
	existing.Spec.Attachment = nwep.Spec.Attachment
	if updErr := c.apiClient.Update(ctx, existing); updErr != nil {
		return false, fmt.Errorf("update existing NetworkEndpoint %s/%s attachment: %w", existing.Namespace, existing.Name, updErr)
	}
	*nwep = *existing
	return false, nil
}

// isNetworkEndpointRace reports whether the error says another writer got
// to the same key first: NotFound from the read that follows an
// AlreadyExists create, Conflict from the update that follows the read.
func isNetworkEndpointRace(err error) bool {
	return apierrors.IsNotFound(err) || apierrors.IsConflict(err)
}

// cleanupVeth best-effort deletes the host-side veth by name. Deleting the
// host side also removes the peer in the pod netns (they share one kernel
// link object). Missing links are treated as success.
func (c *CNIServer) cleanupVeth(name string) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, notFound := err.(netlink.LinkNotFoundError); notFound {
			return
		}
		zap.S().Warnf("rollback: lookup veth %s: %v", name, err)
		return
	}
	if err := netlink.LinkDel(link); err != nil {
		zap.S().Warnf("rollback: delete veth %s: %v", name, err)
		return
	}
	zap.S().Debugf("rollback: deleted veth %s", name)
}

// cleanupNetworkEndpoint best-effort deletes a NetworkEndpoint resource.
// Missing resources are treated as success. Uses a fresh context since the
// caller's context is likely already cancelled on the error path.
func (c *CNIServer) cleanupNetworkEndpoint(nwep *juneauv1alpha1.NetworkEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.apiClient.Delete(ctx, nwep); err != nil {
		if apierrors.IsNotFound(err) {
			return
		}
		zap.S().Warnf("rollback: delete NetworkEndpoint %s/%s: %v", nwep.Namespace, nwep.Name, err)
		return
	}
	zap.S().Debugf("rollback: deleted NetworkEndpoint %s/%s", nwep.Namespace, nwep.Name)
}
