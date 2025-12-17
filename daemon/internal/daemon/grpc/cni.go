package grpc

import (
	"context"
	"reflect"

	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	PodNameKey      = "K8S_POD_NAME"
	PodNamespaceKey = "K8S_POD_NAMESPACE"
)

type CNIServer struct {
	cnipb.UnimplementedCNIServer
}

func (c *CNIServer) Add(ctx context.Context, req *cnipb.CNIRequest) (*cnipb.CNIResponse, error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]

	zap.S().Infof("CNI ADD request for pod %s/%s ifname=%s", podNamespace, podName, req.Ifname)

	vethHostName := c.vethHostName(req.Ifname, req.ContainerId)
	vethPeerName := c.vethPeerName(req.Ifname, req.ContainerId)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: vethHostName,
		},
		PeerName: vethPeerName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		zap.L().Error("failed to create veth pair", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to create veth pair", err.Error())
	}

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
	defer netns.Close()

	if err := netlink.LinkSetNsFd(vethPeer, int(netns.Fd())); err != nil {
		zap.L().Error("failed to move peer veth to netns", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to move peer veth to netns", err.Error())
	}

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
		return nil
	}); err != nil {
		zap.L().Error("failed to setup veth in netns", zap.Error(err))
		return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Failed to setup veth in netns", err.Error())
	}

	return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Unimplemented", "")
}

func (c *CNIServer) Check(ctx context.Context, req *cnipb.CNIRequest) (*emptypb.Empty, error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]

	zap.S().Infof("CNI CHECK request for pod %s/%s ifname=%s", podNamespace, podName, req.Ifname)

	return nil, makeError(cnipb.ErrorCode_TRY_AGAIN_LATER, "Unimplemented", "")
}

func (c *CNIServer) Del(ctx context.Context, req *cnipb.CNIRequest) (*emptypb.Empty, error) {
	podNamespace := req.Args[PodNamespaceKey]
	podName := req.Args[PodNameKey]

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

	return &emptypb.Empty{}, nil
}

func newCNIServer() *CNIServer {
	return &CNIServer{}
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
