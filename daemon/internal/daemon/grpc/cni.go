package grpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// podRefUIDIndex finds every NetworkInterface or NetworkEndpoint of one
// pod instance. A CNI request carries one interface name but covers all
// the NICs of the pod, so the pod UID is the key both directions use.
const podRefUIDIndex = "spec.podRef.uid"

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

// rollback collects the undo of every side effect an ADD produced, so a
// failure half way through leaves the node the way it was found.
type rollback struct {
	steps []func()
}

func (r *rollback) push(step func()) {
	r.steps = append(r.steps, step)
}

func (r *rollback) run() {
	for i := len(r.steps) - 1; i >= 0; i-- {
		r.steps[i]()
	}
}

// podRoute is one route of a NIC, already parsed.
type podRoute struct {
	dst *net.IPNet
	gw  net.IP
}

// attachedInterface is what one attached NIC contributes to the CNI
// result.
type attachedInterface struct {
	ifname  string
	address net.IPNet
	routes  []podRoute
}

func (c *CNIServer) Add(ctx context.Context, req *cnipb.CNIRequest) (resp *cnipb.CNIResponse, retErr error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]
	podUID := req.Args[PodUIDKey]

	zap.S().Infof("CNI ADD request for pod %s/%s ifname=%s containerID=%s", podNamespace, podName, req.Ifname, req.ContainerId)
	zap.S().Debugf("CNI ADD request args: %v", req.Args)

	var undo rollback
	defer func() {
		if retErr == nil {
			return
		}
		zap.S().Warnf("CNI ADD failed for pod %s/%s, rolling back: %v", podNamespace, podName, retErr)
		undo.run()
	}()

	var nwifaceList juneauv1alpha1.NetworkInterfaceList
	if err := c.cachedClient.List(ctx, &nwifaceList, client.InNamespace(podNamespace), client.MatchingFields{
		podRefUIDIndex: podUID,
	}); err != nil {
		zap.L().Error("failed to list NetworkInterface resources", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to list NetworkInterface resources", err.Error())
	}
	if len(nwifaceList.Items) == 0 {
		zap.L().Error("no NetworkInterface resource found for pod")
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "No NetworkInterface resource found for pod", "")
	}

	wanted, err := c.requirePodNetworkAttachments(ctx, podNamespace, podName, podUID)
	if err != nil {
		return nil, err
	}

	nwifaces := orderPodInterfaces(nwifaceList.Items, req.Ifname)
	if err := checkPodInterfacesComplete(nwifaces, wanted); err != nil {
		zap.L().Error("pod NICs are not all provisioned yet", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Pod NetworkInterfaces are not all provisioned yet", err.Error())
	}
	nwifaces = filterPodInterfaces(nwifaces, wanted)
	if err := checkPodInterfacesAllocated(nwifaces); err != nil {
		zap.L().Error("pod NICs are not allocated yet", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Pod NetworkInterfaces are not allocated yet", err.Error())
	}
	if err := checkPrimaryPodInterface(nwifaces, req.Ifname); err != nil {
		zap.L().Error("pod cannot be handed to the container runtime", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_INTERNAL, "Pod has no usable primary NIC", err.Error())
	}

	zap.S().Debugf("Netns: %s, Path: %s", req.Netns, req.Path)

	netns, err := ns.GetNS(req.Netns)
	if err != nil {
		zap.L().Error("failed to open netns", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to open netns", err.Error())
	}
	defer func() {
		_ = netns.Close()
	}()

	res := &types040.Result{
		CNIVersion: "0.4.0",
		Routes:     []*types.Route{},
	}
	var primaryAddress string
	for index, nwiface := range nwifaces {
		attached, err := c.attachPodInterface(ctx, req, netns, index, nwiface, &undo)
		if err != nil {
			return nil, err
		}
		if attached.ifname == req.Ifname {
			primaryAddress = attached.address.String()
		}
		res.Interfaces = append(res.Interfaces, &types040.Interface{
			Name:    attached.ifname,
			Sandbox: req.Netns,
		})
		res.IPs = append(res.IPs, &types040.IPConfig{
			Version:   "4",
			Interface: ptr.To(len(res.Interfaces) - 1),
			Address:   attached.address,
		})
		for _, route := range attached.routes {
			res.Routes = append(res.Routes, &types.Route{Dst: *route.dst, GW: route.gw})
		}
	}

	var buf bytes.Buffer
	if err := res.PrintTo(&buf); err != nil {
		zap.L().Error("failed to serialize CNI result", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to serialize CNI result", err.Error())
	}

	if c.probeRegistrar != nil && req.Ifname == probedPodInterfaceName {
		if err := c.probeRegistrar.RegisterPod(ctx, podNamespace, podName, podUID, req.ContainerId, req.Netns, primaryAddress); err != nil {
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to register Pod probes", err.Error())
		}
		undo.push(func() { _ = c.probeRegistrar.UnregisterPod(podUID, req.ContainerId) })
	}

	return &cnipb.CNIResponse{
		ResultJson: buf.Bytes(),
	}, nil
}

// errPodInstanceGone says the pod instance a CNI request names is not in
// the cache, either because it is deleted or because its name now belongs
// to a newer instance.
var errPodInstanceGone = errors.New("the pod instance of the request is gone")

// errPodNetworksUnreadable says the pod is there but describes NICs
// Juneau cannot build. Retrying does not help.
var errPodNetworksUnreadable = errors.New("the pod asks for NICs Juneau cannot build")

// podNetworkAttachments reads back the NICs the pod asked for. The Pod is
// the only place that says how many NICs to expect, so an ADD consults it
// before deciding the NetworkInterfaces it found are the whole set.
func (c *CNIServer) podNetworkAttachments(ctx context.Context, namespace, name, uid string) ([]juneauv1alpha1.PodNetworkAttachment, error) {
	var pod corev1.Pod
	if err := c.cachedClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: no pod %s/%s", errPodInstanceGone, namespace, name)
		}
		return nil, fmt.Errorf("get pod %s/%s: %w", namespace, name, err)
	}
	if string(pod.UID) != uid {
		return nil, fmt.Errorf("%w: pod %s/%s is instance %s, the request is for %s",
			errPodInstanceGone, namespace, name, pod.UID, uid)
	}
	attachments, err := juneauv1alpha1.PodNetworkAttachments(pod.Annotations)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPodNetworksUnreadable, err)
	}
	return attachments, nil
}

// requirePodNetworkAttachments is podNetworkAttachments for ADD and
// CHECK, which cannot go on without knowing the NICs the pod asks for.
func (c *CNIServer) requirePodNetworkAttachments(ctx context.Context, namespace, name, uid string) ([]juneauv1alpha1.PodNetworkAttachment, error) {
	attachments, err := c.podNetworkAttachments(ctx, namespace, name, uid)
	if err == nil {
		return attachments, nil
	}
	zap.L().Error("cannot read the NICs the pod asks for", zap.Error(err))
	if errors.Is(err, errPodNetworksUnreadable) {
		return nil, makeError(cnipb.ErrorCode_INTERNAL, "The pod asks for NICs Juneau cannot build", err.Error())
	}
	return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to read the NICs the pod asks for", err.Error())
}

// attachPodInterface builds one NIC: a veth pair whose pod side lands in
// the sandbox under the name the NetworkInterface asks for, plus the
// NetworkEndpoint that tells the data plane about it. Every side effect
// is pushed onto undo so a later NIC failing takes this one down too.
func (c *CNIServer) attachPodInterface(
	ctx context.Context,
	req *cnipb.CNIRequest,
	netns ns.NetNS,
	index int,
	nwiface *juneauv1alpha1.NetworkInterface,
	undo *rollback,
) (*attachedInterface, error) {
	ifname := nwiface.Spec.PodRef.Interface
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]
	podUID := req.Args[PodUIDKey]

	vethHost, peerHWAddr, err := c.createPodVeth(ifname, index, req, netns, undo)
	if err != nil {
		return nil, err
	}

	ip, ipnet, err := net.ParseCIDR(nwiface.Status.Address)
	if err != nil {
		zap.L().Error("failed to parse assigned IP address", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to parse assigned IP address", err.Error())
	}

	routes := make([]podRoute, 0, len(nwiface.Status.Routes))
	for _, route := range nwiface.Status.Routes {
		_, dst, err := net.ParseCIDR(route.Dst)
		if err != nil {
			zap.L().Error("failed to parse route destination CIDR", zap.Error(err))
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to parse route destination CIDR", err.Error())
		}
		gw := net.ParseIP(route.GW)
		if gw == nil {
			zap.L().Error("failed to parse route gateway IP", zap.String("gw", route.GW))
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to parse route gateway IP", "")
		}
		routes = append(routes, podRoute{dst: dst, gw: gw})
	}

	address := net.IPNet{IP: ip, Mask: ipnet.Mask}
	if err = netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("failed to find interface %s in netns: %w", ifname, err)
		}

		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &address}); err != nil {
			return fmt.Errorf("failed to assign IP address to interface %s in netns: %w", ifname, err)
		}
		zap.S().Debugf("Assigned IP %s to interface %s in netns", nwiface.Status.Address, ifname)

		for _, route := range routes {
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Gw:        route.gw,
				Dst:       route.dst,
			}); err != nil {
				return fmt.Errorf("failed to add route to interface %s in netns: %w", ifname, err)
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

	nwep := &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: podNamespace,
			Name:      networkEndpointName(podName, ifname),
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
				Interface: ifname,
				UID:       podUID,
			},
			NodeName:   nwiface.Spec.NodeName,
			Subnet:     nwiface.Spec.Subnet,
			Address:    nwiface.Status.Address,
			MACAddress: peerHWAddr.String(),
			Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
				Ifindex:        vethHost.Index,
				HostMACAddress: hostRefreshed.Attrs().HardwareAddr.String(),
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
		undo.push(func() { c.cleanupNetworkEndpoint(nwep) })
	}

	return &attachedInterface{ifname: ifname, address: address, routes: routes}, nil
}

// createPodVeth builds the veth pair of one NIC and moves its pod side
// into the sandbox under the final interface name. It returns the host
// side and the MAC the pod side ended up with.
func (c *CNIServer) createPodVeth(
	ifname string,
	index int,
	req *cnipb.CNIRequest,
	netns ns.NetNS,
	undo *rollback,
) (*netlink.Veth, net.HardwareAddr, error) {
	vethHostName := vethHostName(ifname, req.ContainerId)
	vethPeerName := vethPeerName(index, req.ContainerId)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: vethHostName,
		},
		PeerName: vethPeerName,
	}
	if err := c.createVethPair(veth); err != nil {
		zap.L().Error("failed to create veth pair", zap.Error(err))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to create veth pair", err.Error())
	}
	undo.push(func() { c.cleanupVeth(vethHostName) })

	zap.S().Debugf("Created veth pair: %s <-> %s", vethHostName, vethPeerName)

	vethHostTmp, err := netlink.LinkByName(vethHostName)
	if err != nil {
		zap.L().Error("failed to lookup created veth", zap.Error(err))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to lookup created veth", err.Error())
	}

	vethHost, ok := vethHostTmp.(*netlink.Veth)
	if !ok {
		zap.L().Error("failed to cast veth host link", zap.String("linkType", reflect.TypeOf(vethHostTmp).String()))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to cast veth host link", "")
	}

	vethPeerTmp, err := netlink.LinkByName(vethPeerName)
	if err != nil {
		zap.L().Error("failed to lookup created veth", zap.Error(err))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to lookup created veth", err.Error())
	}

	vethPeer, ok := vethPeerTmp.(*netlink.Veth)
	if !ok {
		zap.L().Error("failed to cast veth peer link", zap.String("linkType", reflect.TypeOf(vethPeerTmp).String()))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to cast veth peer link", "")
	}

	if err := netlink.LinkSetUp(vethHost); err != nil {
		zap.L().Error("failed to bring up veth on host", zap.Error(err))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to bring up veth on host", err.Error())
	}

	if err := netlink.LinkSetNsFd(vethPeer, int(netns.Fd())); err != nil {
		zap.L().Error("failed to move peer veth to netns", zap.Error(err))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to move peer veth to netns", err.Error())
	}

	var peerHWAddr net.HardwareAddr
	if err := netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(vethPeerName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetName(link, ifname); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		refreshed, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("re-lookup peer veth after rename: %w", err)
		}
		peerHWAddr = refreshed.Attrs().HardwareAddr
		return nil
	}); err != nil {
		zap.L().Error("failed to setup veth in netns", zap.Error(err))
		return nil, nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to setup veth in netns", err.Error())
	}

	return vethHost, peerHWAddr, nil
}

func (c *CNIServer) Check(ctx context.Context, req *cnipb.CNIRequest) (*emptypb.Empty, error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]
	podUID := req.Args[PodUIDKey]

	zap.S().Infof("CNI CHECK request for pod %s/%s ifname=%s", podNamespace, podName, req.Ifname)

	// 1. Every NetworkInterface of the pod exists and has been allocated.
	var nwifList juneauv1alpha1.NetworkInterfaceList
	if err := c.cachedClient.List(ctx, &nwifList, client.InNamespace(podNamespace), client.MatchingFields{
		podRefUIDIndex: podUID,
	}); err != nil {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to list NetworkInterface resources", err.Error())
	}
	if len(nwifList.Items) == 0 {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "NetworkInterface not found for pod", "")
	}
	wanted, err := c.requirePodNetworkAttachments(ctx, podNamespace, podName, podUID)
	if err != nil {
		return nil, err
	}
	nwifaces := filterPodInterfaces(orderPodInterfaces(nwifList.Items, req.Ifname), wanted)
	if err := checkPodInterfacesAllocated(nwifaces); err != nil {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Pod NetworkInterfaces are not allocated yet", err.Error())
	}
	if err := checkPrimaryPodInterface(nwifaces, req.Ifname); err != nil {
		return nil, makeError(cnipb.ErrorCode_INTERNAL, "Pod has no usable primary NIC", err.Error())
	}

	// 2. Every NetworkEndpoint exists and agrees with its NetworkInterface.
	var nwepList juneauv1alpha1.NetworkEndpointList
	if err := c.cachedClient.List(ctx, &nwepList, client.InNamespace(podNamespace), client.MatchingFields{
		podRefUIDIndex: podUID,
	}); err != nil {
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to list NetworkEndpoint resources", err.Error())
	}
	endpoints := make(map[string]*juneauv1alpha1.NetworkEndpoint, len(nwepList.Items))
	for i := range nwepList.Items {
		if ref := nwepList.Items[i].Spec.PodRef; ref != nil {
			endpoints[ref.Interface] = &nwepList.Items[i]
		}
	}

	for _, nwif := range nwifaces {
		ifname := nwif.Spec.PodRef.Interface
		nwep, ok := endpoints[ifname]
		if !ok {
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "NetworkEndpoint not found for pod/interface", ifname)
		}
		if nwep.Spec.Address != nwif.Status.Address {
			return nil, makeError(cnipb.ErrorCode_INTERNAL,
				"NetworkEndpoint address disagrees with NetworkInterface",
				fmt.Sprintf("ifname=%s nwep=%s nwif=%s", ifname, nwep.Spec.Address, nwif.Status.Address))
		}

		// 3. Host-side veth for this container exists.
		hostName := vethHostName(ifname, req.ContainerId)
		if _, err := netlink.LinkByName(hostName); err != nil {
			if _, notFound := err.(netlink.LinkNotFoundError); notFound {
				return nil, makeError(cnipb.ErrorCode_INTERNAL, "host-side veth missing", hostName)
			}
			return nil, makeError(cnipb.ErrorCode_INTERNAL, "Failed to lookup host-side veth", err.Error())
		}

		// 4. Pod netns still has the expected interface with the expected IP.
		if err := c.verifyPodInterface(req.Netns, ifname, nwif.Status.Address); err != nil {
			return nil, err
		}
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

	zap.S().Infof("CNI DEL request for pod %s/%s ifname=%s containerID=%s", podNamespace, podName, req.Ifname, req.ContainerId)

	if err := c.deleteSandboxVeths(req.ContainerId); err != nil {
		zap.L().Error("failed to delete veth", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to delete veth", err.Error())
	}

	var nwepList juneauv1alpha1.NetworkEndpointList
	if err := c.cachedClient.List(ctx, &nwepList, client.InNamespace(podNamespace), client.MatchingFields{
		podRefUIDIndex: podUID,
	}); err != nil {
		zap.L().Error("failed to list NetworkEndpoint resources", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to list NetworkEndpoint resources", err.Error())
	}

	// A DEL has to finish even when the pod can no longer be read: the
	// endpoints of a pod that is already gone were removed with its
	// NetworkInterfaces, so the endpoint list is the whole story then.
	wanted, err := c.podNetworkAttachments(ctx, podNamespace, podName, podUID)
	if err != nil {
		zap.S().Debugf("CNI DEL for pod %s/%s takes its NIC names from the endpoints alone: %v", podNamespace, podName, err)
		wanted = nil
	}

	primarySuperseded := false
	for _, ifname := range podNICsToRelease(nwepList.Items, wanted, podName, podUID, req.Ifname) {
		release, err := c.releaseNetworkEndpoint(ctx, podNamespace, podName, podUID, ifname, req.ContainerId)
		if err != nil {
			zap.L().Error("failed to release NetworkEndpoint resource", zap.Error(err))
			return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to release NetworkEndpoint resource", err.Error())
		}
		if release.superseded {
			zap.S().Infof("CNI DEL for pod %s/%s ifname=%s from container %s ignored: %s",
				podNamespace, podName, ifname, req.ContainerId, release.supersededReason())
			if ifname == req.Ifname {
				primarySuperseded = true
			}
		}
	}

	// Unregister Pod probes only for the generation being torn down. A
	// newer sandbox holding the primary endpoint means this DEL is stale
	// and the probes it would release are the live ones.
	if c.probeRegistrar != nil && req.Ifname == probedPodInterfaceName && !primarySuperseded {
		if err := c.probeRegistrar.UnregisterPod(podUID, req.ContainerId); err != nil {
			zap.L().Warn("failed to unregister Pod probes", zap.Error(err))
		}
	}
	return &emptypb.Empty{}, nil
}

// deleteSandboxVeths removes every host veth this sandbox created.
//
// The host itself is the source of truth here rather than the
// NetworkEndpoints, because those can already be gone when a DEL arrives:
// a pod that finished loses its NetworkInterfaces, and the endpoints go
// with them. Every name a link is deleted under is rebuilt from the
// container ID of this very request, so a stale DEL can only ever take
// down links of its own sandbox.
func (c *CNIServer) deleteSandboxVeths(containerID string) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list host links: %w", err)
	}
	for _, link := range links {
		name := link.Attrs().Name
		if !isSandboxVethName(name, containerID) {
			continue
		}
		if err := netlink.LinkDel(link); err != nil {
			if errors.Is(err, syscall.ENODEV) {
				continue
			}
			return fmt.Errorf("delete veth %s: %w", name, err)
		}
		zap.S().Debugf("Deleted veth: %s", name)
	}
	return nil
}

// isSandboxVethName reports whether a host link carries a name Juneau
// built for this container. The check rebuilds the name from the part in
// front of the separator, so it accepts exactly the names vethHostName
// and vethPeerName produce and nothing else.
func isSandboxVethName(name, containerID string) bool {
	prefix, _, found := strings.Cut(name, vethNameSeparator)
	if !found || prefix == "" {
		return false
	}
	return name == vethHostName(prefix, containerID)
}

// networkEndpointRelease says what a CNI DEL found when it went for the
// Pod NetworkEndpoint of its own sandbox. The zero value means no endpoint
// of this sandbox is left: either the DEL deleted it, or none belonged to
// the request.
type networkEndpointRelease struct {
	// superseded is set when a newer sandbox owns the endpoint, so the
	// DEL is stale and has to leave the live attachment alone.
	superseded bool
	// liveContainerID names the container holding the endpoint. It stays
	// empty when a concurrent writer supersedes the DEL without telling
	// us which container won.
	liveContainerID string
}

func (r networkEndpointRelease) supersededReason() string {
	if r.liveContainerID == "" {
		return "another writer changed the endpoint while the DEL was running"
	}
	return fmt.Sprintf("the endpoint is attached to container %s", r.liveContainerID)
}

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
			return networkEndpointRelease{}, nil
		}
		return networkEndpointRelease{}, fmt.Errorf("fetch NetworkEndpoint %s: %w", key, err)
	}

	if !podRefMatches(nwep.Spec.PodRef, podName, podUID, ifname) {
		// The name belongs to another pod instance, so this DEL has no
		// endpoint of its own to remove.
		return networkEndpointRelease{}, nil
	}
	if owner, known := attachmentOwner(nwep.Spec.Attachment); known && owner != containerID {
		return networkEndpointRelease{superseded: true, liveContainerID: owner}, nil
	}

	err := c.apiClient.Delete(ctx, &nwep, client.Preconditions{
		UID:             &nwep.UID,
		ResourceVersion: &nwep.ResourceVersion,
	})
	switch {
	case err == nil, apierrors.IsNotFound(err):
		return networkEndpointRelease{}, nil
	case apierrors.IsConflict(err):
		return networkEndpointRelease{superseded: true}, nil
	default:
		return networkEndpointRelease{}, fmt.Errorf("delete NetworkEndpoint %s: %w", key, err)
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

// attachmentOwner returns the CNI container that recorded the attachment.
// Attachments written before the container ID was recorded carry an empty
// one; report those as unknown so DEL still takes them down and an upgrade
// does not leak endpoints.
func attachmentOwner(attachment *juneauv1alpha1.NetworkEndpointAttachment) (string, bool) {
	if attachment == nil || attachment.ContainerID == "" {
		return "", false
	}
	return attachment.ContainerID, true
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

const (
	// linkNameMaxLen is IFNAMSIZ minus the trailing NUL byte.
	linkNameMaxLen = 15

	// vethNameIDMinLen is the shortest slice of a container ID that still
	// tells two sandboxes of the same pod NIC apart. It is what bounds
	// juneauv1alpha1.PodInterfaceNameMaxLen.
	vethNameIDMinLen = 6

	// vethNameSeparator joins the interface name and the container ID.
	vethNameSeparator = "+"

	// vethPeerNamePrefix holds an underscore so it can never be mistaken
	// for an interface name a pod asked for: those are DNS-1123 labels.
	vethPeerNamePrefix = "tmp_"
)

// probedPodInterfaceName is the NIC kubelet probes reach the pod on. The
// probe proxy rewrites a probe to the pod address of this NIC, so an
// extra NIC never takes probe traffic.
const probedPodInterfaceName = juneauv1alpha1.PodPrimaryInterfaceName

// vethHostName names the host side of one pod NIC. The container ID gets
// whatever room the interface name leaves it inside IFNAMSIZ, which is
// why an interface name may not be longer than
// juneauv1alpha1.PodInterfaceNameMaxLen.
func vethHostName(ifName, containerID string) string {
	return ifName + vethNameSeparator + shortContainerID(containerID, linkNameMaxLen-len(ifName)-len(vethNameSeparator))
}

// vethPeerName names the pod side of a veth while it is still in the host
// netns. It only lives until the link is moved and renamed, so telling
// the NICs of one ADD apart by their position is enough and leaves the
// whole IFNAMSIZ budget to the container ID.
func vethPeerName(index int, containerID string) string {
	return vethHostName(fmt.Sprintf("%s%d", vethPeerNamePrefix, index), containerID)
}

// shortContainerID cuts the container ID down so the link name fits in
// IFNAMSIZ. The CNI spec allows any non-empty container ID, so an ID that
// is already short enough is used whole.
func shortContainerID(containerID string, length int) string {
	if length < 0 {
		length = 0
	}
	if len(containerID) <= length {
		return containerID
	}
	return containerID[:length]
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
	// The preconditions matter here: a rollback can run long after a newer
	// sandbox recreated the same endpoint, and deleting that one would
	// take a running pod off the network.
	if err := c.apiClient.Delete(ctx, nwep, client.Preconditions{
		UID:             &nwep.UID,
		ResourceVersion: &nwep.ResourceVersion,
	}); err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			return
		}
		zap.S().Warnf("rollback: delete NetworkEndpoint %s/%s: %v", nwep.Namespace, nwep.Name, err)
		return
	}
	zap.S().Debugf("rollback: deleted NetworkEndpoint %s/%s", nwep.Namespace, nwep.Name)
}
