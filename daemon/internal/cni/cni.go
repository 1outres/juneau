package cni

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"

	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"k8s.io/utils/ptr"
)

type NetConf struct {
	types.NetConf
}

var ipamClient juneaupb.IPAMClient

func Init() error {
	f, err := os.OpenFile("/var/log/juneau-cni.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	ws := zapcore.AddSync(f)
	encoderCfg := zap.NewDevelopmentEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		ws,
		zap.DebugLevel,
	)

	logger := zap.New(core, zap.AddCaller())
	zap.ReplaceGlobals(logger)

	conn, err := grpc.Dial(
		"unix:///var/run/juneaud.sock",
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	)
	if err != nil {
		zap.L().Error("Failed to connect to juneaud", zap.Error(err))
		return err
	}
	defer conn.Close()

	ipamClient = juneaupb.NewIPAMClient(conn)

	return nil
}

func CmdAdd(args *skel.CmdArgs) error {
	ctx := context.Background()
	zap.L().Info("CmdAdd", zap.String("args", args.Args))

	var netConf *NetConf
	if err := json.Unmarshal(args.StdinData, &netConf); err != nil {
		return &types.Error{
			Code:    types.ErrDecodingFailure,
			Msg:     "Failed to decode CNI config",
			Details: err.Error(),
		}
	}

	cniArgs := parseCNIArgs(args.Args)
	zap.S().Info("CNI Args", zap.Any("args", cniArgs))
	zap.ReplaceGlobals(zap.L().With(zap.String("pod", cniArgs["K8S_POD_NAMESPACE"]+"/"+cniArgs["K8S_POD_NAME"])))

	vethHost := "veth+" + args.ContainerID[0:10]
	vethPeer := args.IfName + "+" + args.ContainerID[0:10]

	// Create veth pair
	veth, err := CreateVethPair(vethHost, vethPeer)
	if err != nil {
		zap.L().Info("Failed to create veth pair", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to create veth pair",
			Details: err.Error(),
		}
	}

	allocateRes, err := ipamClient.Allocate(ctx, &juneaupb.AllocateRequest{
		Id: &juneaupb.CNIIdentity{
			NodeName:      cniArgs["K8S_NODE_NAME"],
			PodNamespace:  cniArgs["K8S_POD_NAMESPACE"],
			PodName:       cniArgs["K8S_POD_NAME"],
			PodUid:        cniArgs["K8S_POD_UID"],
			ContainerId:   args.ContainerID,
			IfName:       args.IfName,
		},
		MacAddress: veth.PeerHardwareAddr.String(),
	})
	if err != nil {
		zap.L().Info("Failed to allocate IP", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to allocate IP",
			Details: err.Error(),
		}
	}
	if !allocateRes.Success {
		zap.L().Info("IP allocation failed", zap.String("message", allocateRes.Error.GetMessage()))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "IP allocation failed",
			Details: allocateRes.Error.GetMessage(),
		}
	}

	// Move one end to netns
	if err := MoveToNetnsAndRename(vethPeer, args.IfName, args.Netns); err != nil {
		zap.L().Info("Failed to move veth to netns", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to move veth to netns",
			Details: err.Error(),
		}
	}

	_, ipnet, _ := net.ParseCIDR(allocateRes.IpAssignment.Ipv4.AddressCidr)
	gateway := net.ParseIP(allocateRes.IpAssignment.Ipv4.Gateway)

	// Set ip address and default route
	if err := SetIPAndRoute(args.IfName, args.Netns, ipnet.String(), gateway.String()); err != nil {
		zap.L().Info("Failed to set IP and route", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to set IP and route",
			Details: err.Error(),
		}
	}

	_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")

	return types.PrintResult(&types100.Result{
		CNIVersion: netConf.CNIVersion,
		Interfaces: []*types100.Interface{
			{
				Name:    args.IfName,
				Sandbox: args.Netns,
			},
		},
		IPs: []*types100.IPConfig{
			{
				Interface: ptr.To(0),
				Address:   *ipnet,
				Gateway:   gateway,
			},
		},
		Routes: []*types.Route{
			{
				Dst: *defaultRoute,
				GW:  gateway,
			},
		},
	}, netConf.CNIVersion)
}

func CmdDel(args *skel.CmdArgs) error {
	return nil
}

func CmdCheck(args *skel.CmdArgs) error {
	return nil
}

func parseCNIArgs(argStr string) map[string]string {
	kvs := make(map[string]string)
	for _, pair := range strings.Split(argStr, ";") {
		if parts := strings.SplitN(pair, "=", 2); len(parts) == 2 {
			kvs[parts[0]] = parts[1]
		}
	}
	return kvs
}
